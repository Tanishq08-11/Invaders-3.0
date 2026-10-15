"""
GET /api/v1/devices/{id}/timeline — return relevant device activity.
=====================================================================
The `id` is the device identifier (typically the IP address).

Returns:
  • The device profile (risk score, alert count, bytes out, flags)
  • A chronological timeline of events from that device
  • A list of alerts tied to that device
"""
from flask import Blueprint, request, jsonify
from core.database import db
from core.models import Device, Event, Alert

bp_devices = Blueprint("devices", __name__, url_prefix="/api/v1/devices")


@bp_devices.route("/<device_id>/timeline", methods=["GET"])
def device_timeline(device_id: str):
    """
    Return the timeline of network activity for a specific device.

    Query params:
      limit  – max events to return (default 50, max 200)
      alerts – if "true", also include alerts (default true)
    """
    device = Device.query.filter_by(device_id=device_id).first()
    if device is None:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    limit = min(200, max(1, int(request.args.get("limit", 50))))
    include_alerts = request.args.get("alerts", "true").lower() in ("true", "1", "yes")

    # Events on this device, newest first
    events = (
        Event.query
        .filter_by(src_ip=device_id)
        .order_by(Event.received_at.desc())
        .limit(limit)
        .all()
    )

    payload = {
        "device": device.to_dict(),
        "timeline": [e.to_dict() for e in reversed(events)],  # chronological
        "event_count": len(events),
    }

    if include_alerts:
        alerts = (
            Alert.query
            .filter_by(src_ip=device_id)
            .order_by(Alert.created_at.desc())
            .limit(limit)
            .all()
        )
        payload["alerts"] = [a.to_summary() for a in alerts]
        payload["alert_count"] = len(alerts)

    return jsonify(payload)


# -----------------------------------------------------------------------
# Bonus: list all tracked devices (useful for the frontend sidebar)
# -----------------------------------------------------------------------
@bp_devices.route("", methods=["GET"])
def list_devices():
    """
    List all tracked internal devices, ranked by risk.

    Query params:
      flagged_only  – "true" to show only quarantined devices
    """
    flagged = request.args.get("flagged_only", "false").lower() in ("true", "1")
    query = Device.query
    if flagged:
        query = query.filter_by(is_flagged=True)

    devices = query.order_by(
        Device.risk_score.desc(),
        Device.alert_count.desc(),
    ).all()

    return jsonify({
        "total": len(devices),
        "devices": [d.to_dict() for d in devices],
    })


@bp_devices.route("/<device_id>/flag", methods=["POST"])
def toggle_flag(device_id: str):
    """Flag or unflag a device for quarantine."""
    device = Device.query.filter_by(device_id=device_id).first()
    if device is None:
        return jsonify({"error": f"Device '{device_id}' not found"}), 404

    data = request.get_json(silent=True) or {}
    device.is_flagged = bool(data.get("is_flagged", not device.is_flagged))
    db.session.commit()

    label = "flagged" if device.is_flagged else "unflagged"
    return jsonify({
        "message": f"Device {device_id} {label}",
        "is_flagged": device.is_flagged,
        "device": device.to_dict(),
    })
