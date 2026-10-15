"""
Schema upgrades for databases created before the event-envelope change.
=========================================================================
The project has no Alembic; tables are created with `db.create_all()`, which never
alters an existing table. `upgrade_schema()` runs right after `create_all()` and brings
older databases up to the current models **without deleting rows**:

  events         + envelope columns (event_type, source, detection_status, …),
                 src_ip / dst_ip become nullable (application events have no 5-tuple),
                 legacy rows are back-filled as event_type=network_record, source=legacy.
  alerts         + source
  file_activity  + security_event_status / _uuid / _payload (outbox, auth database)

Every step inspects the live schema first, so running it again is a no-op.
SQLite cannot drop NOT NULL in place; that one step rebuilds the table inside a
transaction after copying the database file to instance/backups/.
"""
import logging
import os
import shutil
from datetime import datetime, timezone

from sqlalchemy import inspect
from sqlalchemy.schema import CreateTable

from core.database import db
from core.models import Alert, Event, FileActivity

log = logging.getLogger(__name__)

# New events columns: name -> DDL used by ALTER TABLE ADD COLUMN (NOT NULL ones need a default).
_EVENT_COLUMNS = {
    "event_type":        "VARCHAR(32) NOT NULL DEFAULT 'network_record'",
    "source":            "VARCHAR(32) NOT NULL DEFAULT 'legacy'",
    "dedup_key":         "VARCHAR(160)",
    "processing_status": "VARCHAR(24) NOT NULL DEFAULT 'complete'",
    "processing_error":  "TEXT",
    "detection_status":  "VARCHAR(24) NOT NULL DEFAULT 'pending'",
    "user_id":           "INTEGER",
    "device_id":         "VARCHAR(64)",
    "action":            "VARCHAR(32)",
    "outcome":           "VARCHAR(16)",
    "flow_id":           "VARCHAR(40)",
    "direction":         "VARCHAR(16)",
    "details_json":      "TEXT",
}

# Legacy rows: derive detection_status from the AI outcome the row already recorded.
_LEGACY_DETECTION_STATUS = (
    "CASE WHEN ai_processed THEN 'scored' "
    "WHEN ai_error LIKE 'Model not loaded%' THEN 'unavailable' "
    "WHEN ai_error IS NOT NULL THEN 'failed' ELSE 'pending' END"
)


def _columns(engine, table):
    return {c["name"]: c for c in inspect(engine).get_columns(table)}


def _backup_sqlite(engine) -> str:
    path = engine.url.database
    if not path or path == ":memory:" or not os.path.isfile(path):
        return ""
    backup_dir = os.path.join(os.path.dirname(path), "backups")
    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(backup_dir, f"{os.path.splitext(os.path.basename(path))[0]}.{stamp}.db")
    shutil.copy2(path, dest)
    return dest


def _rebuild_sqlite_events(engine, existing_cols) -> None:
    """Recreate `events` from the current model and copy every row across."""
    backup = _backup_sqlite(engine)
    table = Event.__table__
    new_cols = [c.name for c in table.columns]
    select_exprs = []
    for name in new_cols:
        if name in existing_cols:
            select_exprs.append(f'"{name}"')
        elif name == "event_type":
            select_exprs.append("'network_record'")
        elif name == "source":
            select_exprs.append("'legacy'")
        elif name == "processing_status":
            select_exprs.append("'complete'")
        elif name == "detection_status":
            select_exprs.append(_LEGACY_DETECTION_STATUS)
        else:
            select_exprs.append("NULL")

    ddl = str(CreateTable(table).compile(engine)).strip()
    assert ddl.startswith("CREATE TABLE events ")
    ddl = ddl.replace("CREATE TABLE events ", "CREATE TABLE events__new ", 1)
    cols_sql = ", ".join(f'"{c}"' for c in new_cols)

    with engine.begin() as conn:
        for idx in inspect(conn).get_indexes("events"):
            if idx.get("name"):
                conn.exec_driver_sql(f'DROP INDEX IF EXISTS "{idx["name"]}"')
        conn.exec_driver_sql(ddl)
        conn.exec_driver_sql(
            f"INSERT INTO events__new ({cols_sql}) SELECT {', '.join(select_exprs)} FROM events"
        )
        conn.exec_driver_sql("DROP TABLE events")
        conn.exec_driver_sql("ALTER TABLE events__new RENAME TO events")
        for idx in table.indexes:
            idx.create(bind=conn, checkfirst=True)
    log.warning("[migrations] rebuilt events table (backup: %s)", backup or "n/a")


def _upgrade_events(engine) -> list:
    done = []
    cols = _columns(engine, "events")
    needs_nullable = not cols["src_ip"]["nullable"] or not cols["dst_ip"]["nullable"]

    if needs_nullable and engine.dialect.name == "sqlite":
        _rebuild_sqlite_events(engine, set(cols))
        return ["events: rebuilt with envelope columns and nullable src_ip/dst_ip"]

    with engine.begin() as conn:
        missing = [c for c in _EVENT_COLUMNS if c not in cols]
        for name in missing:
            conn.exec_driver_sql(f"ALTER TABLE events ADD COLUMN {name} {_EVENT_COLUMNS[name]}")
        if missing:
            done.append(f"events: added {', '.join(missing)}")
            if "detection_status" in missing:
                conn.exec_driver_sql(f"UPDATE events SET detection_status = {_LEGACY_DETECTION_STATUS}")
        if needs_nullable:  # PostgreSQL and other dialects that support it in place
            conn.exec_driver_sql("ALTER TABLE events ALTER COLUMN src_ip DROP NOT NULL")
            conn.exec_driver_sql("ALTER TABLE events ALTER COLUMN dst_ip DROP NOT NULL")
            done.append("events: src_ip/dst_ip nullable")
        existing_idx = {i["name"] for i in inspect(conn).get_indexes("events")}
        for idx in Event.__table__.indexes:
            if idx.name not in existing_idx:
                idx.create(bind=conn, checkfirst=True)
                done.append(f"events: index {idx.name}")
    return done


def _add_columns(engine, table_name, model, columns: dict) -> list:
    cols = _columns(engine, table_name)
    missing = [c for c in columns if c not in cols]
    if not missing:
        return []
    with engine.begin() as conn:
        for name in missing:
            conn.exec_driver_sql(f"ALTER TABLE {table_name} ADD COLUMN {name} {columns[name]}")
        existing_idx = {i["name"] for i in inspect(conn).get_indexes(table_name)}
        for idx in model.__table__.indexes:
            if idx.name not in existing_idx:
                idx.create(bind=conn, checkfirst=True)
    return [f"{table_name}: added {', '.join(missing)}"]


def upgrade_schema() -> list:
    """Bring existing databases up to the current models. Returns the steps applied."""
    applied = []
    main = db.engine
    applied += _upgrade_events(main)
    applied += _add_columns(main, "alerts", Alert, {"source": "VARCHAR(32)"})

    auth = db.engines.get("auth", main)
    applied += _add_columns(auth, "file_activity", FileActivity, {
        "security_event_status": "VARCHAR(16)",
        "security_event_uuid": "VARCHAR(64)",
        "security_event_payload": "TEXT",
    })
    for step in applied:
        log.warning("[migrations] %s", step)
    return applied
