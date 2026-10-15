"""
Schema upgrades for databases created before the event-envelope change.
=========================================================================
The project has no Alembic; tables are created with `db.create_all()`, which never
alters an existing table. `upgrade_schema()` runs right after `create_all()` and brings
older databases up to the current models **without deleting rows**:

  events         + envelope columns (event_type, source, detection_status, …),
                 src_ip / dst_ip become nullable (application events have no 5-tuple),
                 legacy rows are back-filled as event_type=network_record, source=legacy.
  alerts         + source, detection_source (ai|rules|hybrid), rule_score, rule signals;
                 anomaly_score / z_score / src_ip / dst_ip become nullable so rule-only
                 alerts never need a fabricated model score (existing scores are kept)
  events         + entity_key, detection_summary_json
  file_activity  + security_event_status / _uuid / _payload (outbox, auth database)

Every step inspects the live schema first, so running it again is a no-op.
SQLite cannot drop NOT NULL in place; those steps rebuild the table inside a
transaction after copying the database file to instance/backups/. New tables
(detection_signals, baseline_samples, behavior_state, destination_history,
registered_devices, device_bindings, auth_sessions) are created by create_all().
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
    "entity_key":        "VARCHAR(96)",
    "detection_summary_json": "TEXT",
}

_ALERT_COLUMNS = {
    "source":            "VARCHAR(32)",
    "detection_source":  "VARCHAR(16) NOT NULL DEFAULT 'ai'",
    "rule_score":        "FLOAT",
    "rule_signals_json": "TEXT",
    "signal_count":      "INTEGER NOT NULL DEFAULT 0",
    "event_type":        "VARCHAR(32)",
    "entity_key":        "VARCHAR(96)",
    "user_id":           "INTEGER",
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
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = os.path.join(backup_dir, f"{os.path.splitext(os.path.basename(path))[0]}.{stamp}.db")
    shutil.copy2(path, dest)
    return dest


def _rebuild_sqlite_table(engine, model, existing_cols, fill: dict) -> str:
    """
    Recreate `model`'s table from the current model definition and copy every row across
    (columns that already exist are copied verbatim; new ones get `fill[name]` or NULL).
    The database file is backed up first. Runs in one transaction.
    """
    backup = _backup_sqlite(engine)
    table = model.__table__
    name = table.name
    new_cols = [c.name for c in table.columns]
    select_exprs = [f'"{c}"' if c in existing_cols else fill.get(c, "NULL") for c in new_cols]

    ddl = str(CreateTable(table).compile(engine)).strip()
    prefix = f"CREATE TABLE {name} "
    assert ddl.startswith(prefix), ddl[:60]
    ddl = ddl.replace(prefix, f"CREATE TABLE {name}__new ", 1)
    cols_sql = ", ".join(f'"{c}"' for c in new_cols)

    with engine.begin() as conn:
        for idx in inspect(conn).get_indexes(name):
            if idx.get("name"):
                conn.exec_driver_sql(f'DROP INDEX IF EXISTS "{idx["name"]}"')
        conn.exec_driver_sql(ddl)
        conn.exec_driver_sql(f"INSERT INTO {name}__new ({cols_sql}) SELECT {', '.join(select_exprs)} FROM {name}")
        conn.exec_driver_sql(f"DROP TABLE {name}")
        conn.exec_driver_sql(f"ALTER TABLE {name}__new RENAME TO {name}")
        for idx in table.indexes:
            idx.create(bind=conn, checkfirst=True)
    log.warning("[migrations] rebuilt %s table (backup: %s)", name, backup or "n/a")
    return backup


def _create_missing_indexes(conn, model) -> list:
    existing_idx = {i["name"] for i in inspect(conn).get_indexes(model.__table__.name)}
    made = []
    for idx in model.__table__.indexes:
        if idx.name not in existing_idx:
            idx.create(bind=conn, checkfirst=True)
            made.append(idx.name)
    return made


def _upgrade_table(engine, model, add_columns: dict, nullable: tuple, fill: dict, post_add_sql: dict = None) -> list:
    """
    Generic upgrade: make `nullable` columns nullable and add `add_columns`.
    SQLite → table rebuild (only if a NOT NULL must be relaxed); other dialects → ALTER.
    `post_add_sql` maps a newly added column to an UPDATE back-fill expression.
    """
    name = model.__table__.name
    cols = _columns(engine, name)
    relax = [c for c in nullable if c in cols and not cols[c]["nullable"]]
    missing = [c for c in add_columns if c not in cols]

    if relax and engine.dialect.name == "sqlite":
        _rebuild_sqlite_table(engine, model, set(cols), fill)
        return [f"{name}: rebuilt (nullable {', '.join(relax)}; added {', '.join(missing) or 'nothing'})"]

    done = []
    with engine.begin() as conn:
        for col in missing:
            conn.exec_driver_sql(f"ALTER TABLE {name} ADD COLUMN {col} {add_columns[col]}")
            if post_add_sql and col in post_add_sql:
                conn.exec_driver_sql(f"UPDATE {name} SET {col} = {post_add_sql[col]}")
        if missing:
            done.append(f"{name}: added {', '.join(missing)}")
        for col in relax:  # PostgreSQL and other dialects that support it in place
            conn.exec_driver_sql(f"ALTER TABLE {name} ALTER COLUMN {col} DROP NOT NULL")
        if relax:
            done.append(f"{name}: nullable {', '.join(relax)}")
        made = _create_missing_indexes(conn, model)
        if made:
            done.append(f"{name}: indexes {', '.join(made)}")
    return done


def _upgrade_events(engine) -> list:
    return _upgrade_table(
        engine, Event, _EVENT_COLUMNS, nullable=("src_ip", "dst_ip"),
        fill={
            "event_type": "'network_record'", "source": "'legacy'",
            "processing_status": "'complete'", "detection_status": _LEGACY_DETECTION_STATUS,
        },
        post_add_sql={"detection_status": _LEGACY_DETECTION_STATUS},
    )


def _upgrade_alerts(engine) -> list:
    # Existing alerts were all produced by the model path: keep their scores exactly as
    # stored and mark them detection_source='ai'. Nothing is zero-filled.
    return _upgrade_table(
        engine, Alert, _ALERT_COLUMNS, nullable=("anomaly_score", "z_score", "src_ip", "dst_ip"),
        fill={"detection_source": "'ai'", "signal_count": "0"},
    )


def upgrade_schema() -> list:
    """Bring existing databases up to the current models. Returns the steps applied."""
    applied = []
    main = db.engine
    applied += _upgrade_events(main)
    applied += _upgrade_alerts(main)

    auth = db.engines.get("auth", main)
    applied += _upgrade_table(auth, FileActivity, {
        "security_event_status": "VARCHAR(16)",
        "security_event_uuid": "VARCHAR(64)",
        "security_event_payload": "TEXT",
    }, nullable=(), fill={})
    for step in applied:
        log.warning("[migrations] %s", step)
    return applied
