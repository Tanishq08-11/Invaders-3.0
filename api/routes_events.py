"""
Event ingestion and the SOC event log.
=======================================
POST /api/v1/events           — ingest external network events (records, flows or packets)
GET  /api/v1/events           — event log (all event types), newest first, keyset-paginated
GET  /api/v1/events/stats     — counts by type / source / detection status
GET  /api/v1/events/<uuid>    — one event with its correlations and related evidence

Ingestion accepts only network evidence. Application activity is recorded by the portal
itself (api/routes_files.py) from the authenticated session — a caller can never submit
an application event or attach a user identity here. Ingested events are always
source="api": a client cannot label its data as live capture.
"""
import ipaddress
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify
from sqlalchemy import func

from core.database import db
from core.models import (
    EVENT_APPLICATION, EVENT_NETWORK_FLOW, EVENT_NETWORK_PACKET, EVENT_NETWORK_RECORD, EVENT_TYPES,
    SOURCE_API, Alert, Event, EventCorrelation, User,
)
from services.event_processor import EventProcessor

bp_events = Blueprint("events", __name__, url_prefix="/api/v1/events")

INGESTIBLE_TYPES = (EVENT_NETWORK_RECORD, EVENT_NETWORK_FLOW, EVENT_NETWORK_PACKET)
IDENTITY_FIELDS = ("user_id", "username", "device_id", "event_type", "source")
MAX_BATCH = 500


def _validate(ev: dict):
    """Returns (event_type, cleaned event, error message)."""
    event_type = ev.get("event_type") or EVENT_NETWORK_RECORD
    if event_type not in INGESTIBLE_TYPES:
        return None, None, (
            f"event_type '{event_type}' cannot be ingested here; allowed: {', '.join(INGESTIBLE_TYPES)}. "
            "Application activity is recorded by the portal itself."
        )
    if not (ev.get("src_ip") or ev.get("saddr")):
        return None, None, "Missing required field: provide at least 'src_ip' (or 'saddr')"
    for field in ("src_ip", "saddr", "dst_ip", "daddr"):
        if ev.get(field) is not None:
            try:
                ipaddress.ip_address(str(ev[field]).strip())
            except ValueError:
                return None, None, f"Invalid IP address in '{field}'."
    cleaned = {k: v for k, v in ev.items() if k not in IDENTITY_FIELDS}
    return event_type, cleaned, None


def _submit(proc, ev):
    event_type, cleaned, err = _validate(ev)
    if err:
        return {"error": err}
    event_id = cleaned.pop("event_id", None)
    dedup = f"api:{str(event_id)[:120]}" if event_id else None
    return proc.submit(cleaned, event_type=event_type, source=SOURCE_API, dedup_key=dedup)


@bp_events.route("", methods=["POST"])
def ingest_events():
    """
    Single event body:  { "src_ip": "192.168.1.105", "dst_ip": "198.51.100.77", … }
    Batch body:         { "events": [ {…}, {…} ] }        (max 500 per request)
    Optional per event: "event_type" (network_record | network_flow | network_packet),
                        "event_id" (idempotency key — resubmission returns the stored event).
    """
    data = request.get_json(silent=True)
    if data is None or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a valid JSON object"}), 400

    proc = EventProcessor.get_instance()

    if "events" in data and isinstance(data["events"], list):
        events_list = data["events"]
        if not events_list:
            return jsonify({"error": "The 'events' array is empty"}), 400
        if len(events_list) > MAX_BATCH:
            return jsonify({"error": f"At most {MAX_BATCH} events per request."}), 413
        valid_events = [e for e in events_list if isinstance(e, dict)]
        if not valid_events:
            return jsonify({"error": "No valid event objects in 'events' array"}), 400
        results = [_submit(proc, ev) for ev in valid_events]
        return jsonify({
            "total_processed": len(results),
            "stored": sum(1 for r in results if "error" not in r),
            "threats_detected": sum(1 for r in results if r.get("alert")),
            "errors": sum(1 for r in results if r.get("error") or r.get("_warning")),
            "results": results,
        }), 201

    result = _submit(proc, data)
    if "error" in result and "id" not in result:
        status = 400 if "could not be stored" not in result["error"] else 503
        return jsonify(result), status
    # 201 when the detector scored it; 202 when stored without a score (unavailable/unsupported/failed).
    return jsonify(result), 201 if result.get("ai_processed") else 202


# ---------------------------------------------------------------------------
# Event log (SOC — guarded by install_soc_guard)
# ---------------------------------------------------------------------------
def _users_by_id(ids):
    ids = {i for i in ids if i}
    if not ids:
        return {}
    rows = User.query.filter(User.id.in_(ids)).all()
    return {u.id: {"username": u.username, "display_name": u.display_name, "department": u.department} for u in rows}


def _with_users(dicts):
    users = _users_by_id(d.get("user_id") for d in dicts)
    for d in dicts:
        d["user"] = users.get(d.get("user_id"))
    return dicts


def _parse_time(raw):
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


@bp_events.route("", methods=["GET"])
def list_events():
    """
    Query params: type (comma list), source, detection_status, user_id, src_ip, flow_id,
    since (ISO-8601), before_id (keyset cursor), limit (default 100, max 500).
    """
    try:
        limit = min(500, max(1, int(request.args.get("limit", 100))))
        before_id = int(request.args["before_id"]) if request.args.get("before_id") else None
        user_id = int(request.args["user_id"]) if request.args.get("user_id") else None
    except ValueError:
        return jsonify({"error": "limit, before_id and user_id must be integers"}), 400

    q = Event.query
    types = [t for t in (request.args.get("type") or "").split(",") if t]
    if any(t not in EVENT_TYPES for t in types):
        return jsonify({"error": f"type must be one of {', '.join(EVENT_TYPES)}"}), 400
    if types:
        q = q.filter(Event.event_type.in_(types))
    for field in ("source", "detection_status", "src_ip", "flow_id"):
        if request.args.get(field):
            q = q.filter(getattr(Event, field) == request.args[field])
    if user_id is not None:
        q = q.filter(Event.user_id == user_id)
    since = _parse_time(request.args.get("since"))
    if since is False:
        return jsonify({"error": "since must be an ISO-8601 timestamp"}), 400
    if since:
        q = q.filter(Event.received_at >= since)
    if before_id:
        q = q.filter(Event.id < before_id)

    rows = q.order_by(Event.id.desc()).limit(limit + 1).all()
    more = len(rows) > limit
    rows = rows[:limit]
    items = _with_users([EventProcessor.summary(r) for r in rows])
    return jsonify({
        "items": items,
        "next_before_id": rows[-1].id if more and rows else None,
    })


@bp_events.route("/stats", methods=["GET"])
def event_stats():
    def grouped(col):
        return {k or "unknown": c for k, c in db.session.query(col, func.count(Event.id)).group_by(col).all()}
    return jsonify({
        "by_type": grouped(Event.event_type),
        "by_source": grouped(Event.source),
        "by_detection_status": grouped(Event.detection_status),
        "correlations": EventCorrelation.query.count(),
        "processor": EventProcessor.get_instance().counters(),
    })


@bp_events.route("/<event_uuid>", methods=["GET"])
def get_event(event_uuid: str):
    ev = Event.query.filter_by(event_uuid=event_uuid).first()
    if ev is None:
        return jsonify({"error": f"Event '{event_uuid}' not found"}), 404
    payload = _with_users([ev.to_dict()])[0]
    payload.pop("raw_event_json", None)

    links = EventCorrelation.query.filter(
        db.or_(EventCorrelation.application_event_id == ev.id, EventCorrelation.network_event_id == ev.id)
    ).order_by(EventCorrelation.created_at.desc()).limit(100).all()
    related_ids = {l.application_event_id for l in links} | {l.network_event_id for l in links}
    related_ids.discard(ev.id)
    related = {r.id: EventProcessor.summary(r) for r in Event.query.filter(Event.id.in_(related_ids)).all()} if related_ids else {}
    _with_users(list(related.values()))
    payload["correlations"] = [
        {**l.to_dict(), "related_event": related.get(l.network_event_id if l.application_event_id == ev.id else l.application_event_id)}
        for l in links
    ]
    if ev.event_type == EVENT_NETWORK_FLOW and ev.flow_id:
        payload["packet_event_count"] = Event.query.filter(
            Event.flow_id == ev.flow_id, Event.event_type == EVENT_NETWORK_PACKET
        ).count()
    if ev.event_type == EVENT_NETWORK_PACKET and ev.flow_id:
        flow = Event.query.filter_by(flow_id=ev.flow_id, event_type=EVENT_NETWORK_FLOW).first()
        payload["flow_event_uuid"] = flow.event_uuid if flow else None
    if ev.alert_id:
        alert = db.session.get(Alert, ev.alert_id)
        payload["alert"] = alert.to_summary() if alert else None
    if ev.event_type == EVENT_APPLICATION:
        payload["note"] = (
            "Application evidence recorded by the portal from an authenticated session. "
            "It is context for investigation and is never used as model input."
        )
    return jsonify(payload)
