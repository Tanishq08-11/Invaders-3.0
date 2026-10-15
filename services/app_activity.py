"""
Application activity → security event (outbox pattern)
=======================================================
The portal's FileActivity rows live in the users database; security events live in the
SOC database. They cannot share a transaction, so:

  1. The file operation and its FileActivity row commit together (users DB), with
     security_event_status="pending" and a small payload (client address, file id,
     size, mime type, location — never file contents or storage paths).
  2. The application_activity event is then recorded through the EventProcessor
     (idempotent: dedup key "file_activity:<id>").
  3. The FileActivity row is marked "recorded" (with the event uuid) or "failed".

Pending/failed rows are retried at startup and after later activity, so a SOC database
outage never loses the employee-visible activity record nor the security event.
"""
import json
import logging
from typing import Any, Dict, Optional

from core.database import db
from core.models import FileActivity

log = logging.getLogger(__name__)

STATUS_PENDING, STATUS_RECORDED, STATUS_FAILED = "pending", "recorded", "failed"


def new_activity(user, action: str, result: str, *, client_ip: Optional[str],
                 file_name: Optional[str] = None, detail: Optional[str] = None,
                 context: Optional[Dict[str, Any]] = None) -> FileActivity:
    """Stage a FileActivity row (caller commits, together with the file operation)."""
    act = FileActivity(
        user_id=user.id, action=action, result=result,
        file_name=file_name[:255] if file_name else None,
        detail=detail[:255] if detail else None,
        security_event_status=STATUS_PENDING,
        security_event_payload=json.dumps({"client_ip": client_ip, "context": context or {}}),
    )
    db.session.add(act)
    return act


def forward(act: FileActivity) -> bool:
    """Record the security event for one committed FileActivity row. Never raises."""
    from services.event_processor import EventProcessor
    try:
        payload = json.loads(act.security_event_payload or "{}")
        res = EventProcessor.get_instance().record_application_activity(
            activity_id=act.id,
            user_id=act.user_id,
            action=act.action,
            outcome=act.result,
            occurred_at=act.timestamp,
            client_ip=payload.get("client_ip"),
            context=payload.get("context") or {},
        )
        ok = isinstance(res, dict) and "error" not in res
    except Exception:
        log.exception("[app_activity] recording security event for activity %s failed", act.id)
        db.session.rollback()
        res, ok = None, False
    try:
        if ok:
            act.security_event_status = STATUS_RECORDED
            act.security_event_uuid = res.get("event_uuid")
            act.security_event_payload = None
        else:
            act.security_event_status = STATUS_FAILED
        db.session.commit()
    except Exception:
        db.session.rollback()
        log.exception("[app_activity] could not update outbox state for activity %s", act.id)
    return ok


def retry_pending(limit: int = 50) -> Dict[str, int]:
    """Re-forward FileActivity rows whose security event is pending or failed."""
    rows = (
        FileActivity.query
        .filter(FileActivity.security_event_status.in_((STATUS_PENDING, STATUS_FAILED)))
        .order_by(FileActivity.id.asc())
        .limit(limit)
        .all()
    )
    done = sum(1 for r in rows if forward(r))
    return {"attempted": len(rows), "recorded": done}


def pending_count() -> int:
    return FileActivity.query.filter(
        FileActivity.security_event_status.in_((STATUS_PENDING, STATUS_FAILED))
    ).count()
