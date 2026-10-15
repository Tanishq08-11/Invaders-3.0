"""
GET  /api/v1/alerts          — list alerts, with severity and status filters.
GET  /api/v1/alerts/{id}     — retrieve one alert and its supporting evidence.
PATCH /api/v1/alerts/{id}    — update the analyst's disposition or status.
"""
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from core.database import db
from core.auth import current_user
from core.models import Alert, AnalystAction, Event

bp_alerts = Blueprint("alerts", __name__, url_prefix="/api/v1/alerts")


# -----------------------------------------------------------------------
# GET /api/v1/alerts
# -----------------------------------------------------------------------
@bp_alerts.route("", methods=["GET"])
def list_alerts():
    """
    List alerts with optional filters and cursor-based pagination.

    Query params:
      severity   – filter by severity (e.g. HIGH, CRITICAL)
      status     – filter by lifecycle status (open, investigating, resolved, …)
      src_ip     – partial match on source IP
      page       – page number (default 1)
      per_page   – items per page (default 20, max 1000)
      sort       – field to sort by (default: created_at)
      order      – asc | desc (default: desc)
    """
    severity  = request.args.get("severity")
    status    = request.args.get("status")
    src_ip    = request.args.get("src_ip")
    page      = max(1, int(request.args.get("page", 1)))
    per_page  = min(1000, max(1, int(request.args.get("per_page", 20))))
    sort_field = request.args.get("sort", "created_at")
    order     = request.args.get("order", "desc").lower()

    query = Alert.query

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status:
        query = query.filter(Alert.status == status.lower())
    if src_ip:
        query = query.filter(Alert.src_ip.contains(src_ip))

    # Dynamic sort
    col = getattr(Alert, sort_field, Alert.created_at)
    if order == "asc":
        query = query.order_by(col.asc())
    else:
        query = query.order_by(col.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    summaries = [a.to_summary() for a in pagination.items]
    return jsonify({
        "total":    pagination.total,
        "page":     pagination.page,
        "pages":    pagination.pages,
        "per_page": pagination.per_page,
        "alerts":   summaries,
        "items":    summaries,  # dashboard contract
    })


# -----------------------------------------------------------------------
# GET /api/v1/alerts/{id}
# -----------------------------------------------------------------------
@bp_alerts.route("/<identifier>", methods=["GET"])
def get_alert(identifier: str):
    """
    Retrieve one alert with full supporting evidence.

    `identifier` may be a numeric ID or the alert_uuid string.

    The response includes:
      • The AI anomaly score, z-score, risk score
      • Top contributing features (evidence) from the XAI engine
      • The human-readable SOC narrative (explanation)
      • Recommended mitigation / playbook steps
      • The originating event(s) that triggered the alert
      • The audit trail of analyst actions
    """
    alert = _resolve_alert(identifier)
    if alert is None:
        return jsonify({"error": f"Alert '{identifier}' not found"}), 404

    # Gather supporting evidence
    source_events = [
        e.to_dict() for e in
        Event.query.filter_by(alert_id=alert.id)
            .order_by(Event.received_at.desc())
            .limit(50)
            .all()
    ]

    actions = [
        a.to_dict() for a in
        AnalystAction.query.filter_by(alert_id=alert.id)
            .order_by(AnalystAction.performed_at.desc())
            .all()
    ]

    payload = alert.to_dict()
    payload["source_events"] = source_events
    payload["events"] = source_events  # dashboard contract
    payload["analyst_actions"] = actions
    return jsonify(payload)


# -----------------------------------------------------------------------
# PATCH /api/v1/alerts/{id}
# -----------------------------------------------------------------------
@bp_alerts.route("/<identifier>", methods=["PATCH"])
def update_alert(identifier: str):
    """
    Update the analyst's disposition or status on an alert.

    Accepted body fields:
      status      – open | investigating | resolved | dismissed
                    (dashboard aliases: new → open, false_positive → dismissed
                     with disposition false_positive)
      disposition – true_positive | false_positive | benign | inconclusive
      analyst_notes – free-text investigation notes (alias: note)
      analyst     – name or ID of the analyst making the change
                    (defaults to the signed-in user)
    """
    alert = _resolve_alert(identifier)
    if alert is None:
        return jsonify({"error": f"Alert '{identifier}' not found"}), 404

    data = dict(request.get_json(silent=True) or {})
    user = current_user()
    analyst_name = data.get("analyst") or (user.username if user else "anonymous")
    now = datetime.now(timezone.utc)
    changes = []

    if "note" in data and "analyst_notes" not in data:
        data["analyst_notes"] = data["note"]
    if isinstance(data.get("status"), str):
        raw_status = data["status"].strip().lower()
        if raw_status == "new":
            data["status"] = "open"
        elif raw_status == "false_positive":
            data["status"] = "dismissed"
            data.setdefault("disposition", "false_positive")

    # --- status ---
    if "status" in data:
        new_status = str(data["status"]).lower()
        valid = ("open", "investigating", "resolved", "dismissed")
        if new_status not in valid:
            return jsonify({"error": f"Invalid status '{new_status}'. Must be one of {valid}"}), 400
        if new_status != alert.status:
            changes.append(AnalystAction(
                alert_id=alert.id,
                action_type="status_change",
                field_name="status",
                old_value=alert.status,
                new_value=new_status,
                analyst=analyst_name,
            ))
            alert.status = new_status
            if new_status in ("resolved", "dismissed"):
                alert.resolved_at = now

    # --- disposition ---
    if "disposition" in data:
        new_disp = data["disposition"].lower()
        valid_disp = ("true_positive", "false_positive", "benign", "inconclusive")
        if new_disp not in valid_disp:
            return jsonify({"error": f"Invalid disposition '{new_disp}'. Must be one of {valid_disp}"}), 400
        if new_disp != alert.disposition:
            changes.append(AnalystAction(
                alert_id=alert.id,
                action_type="disposition_set",
                field_name="disposition",
                old_value=alert.disposition,
                new_value=new_disp,
                analyst=analyst_name,
            ))
            alert.disposition = new_disp
            # Update counters on the processor for metrics
            from services.event_processor import EventProcessor
            proc = EventProcessor.get_instance()
            if new_disp == "true_positive":
                proc.true_positives += 1
            elif new_disp == "false_positive":
                proc.false_positives += 1

    # --- analyst notes ---
    if "analyst_notes" in data and (data["analyst_notes"] or "") != (alert.analyst_notes or ""):
        old_notes = alert.analyst_notes or ""
        alert.analyst_notes = data["analyst_notes"]
        changes.append(AnalystAction(
            alert_id=alert.id,
            action_type="note_added",
            field_name="analyst_notes",
            old_value=old_notes[:120] if old_notes else None,
            new_value=data["analyst_notes"][:120],
            analyst=analyst_name,
        ))

    alert.updated_at = now
    for action in changes:
        db.session.add(action)

    db.session.commit()

    return jsonify({
        "message": f"Alert updated ({len(changes)} change(s) recorded)",
        "alert": alert.to_dict(),
    })


# -----------------------------------------------------------------------
# Helper
# -----------------------------------------------------------------------
def _resolve_alert(identifier: str):
    if identifier.isdigit():
        return db.session.get(Alert, int(identifier))
    return Alert.query.filter_by(alert_uuid=identifier).first()
