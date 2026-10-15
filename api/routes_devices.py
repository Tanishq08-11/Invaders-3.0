"""
GET /api/v1/devices/{id}/timeline — return relevant device activity.
=====================================================================
The `id` is the device identifier (typically the IP address).

Returns:
  • The device profile (risk score, alert count, bytes out, flags)
  • A chronological timeline of events from that device
  • A list of alerts tied to that device
"""
from collections import Counter
from datetime import timezone
from statistics import median

from flask import Blueprint, request, jsonify
from core.database import db
from core.data_source import current_data_source
from core.models import Device, Event, Alert, iso_utc, TRAFFIC_EVENT_TYPES

bp_devices = Blueprint("devices", __name__, url_prefix="/api/v1/devices")

BASELINE_EVENTS = 2000   # history window used for baseline / burst analysis
BURST_MIN_CONNECTIONS = 5


def _event_time(e):
    t = e.event_time or e.received_at
    return t.replace(tzinfo=timezone.utc) if t is not None and t.tzinfo is None else t


def _behaviour_profile(device_id: str, alert_dsts: set):
    """
    Baseline, unusual destinations and connection bursts derived from the device's
    recent event history (metadata only).
    """
    history = (
        Event.query.filter(Event.src_ip == device_id, Event.event_type.in_(TRAFFIC_EVENT_TYPES))
        .order_by(Event.received_at.desc())
        .limit(BASELINE_EVENTS)
        .all()
    )
    if not history:
        return None, [], []

    times = [t for t in (_event_time(e) for e in history) if t is not None]
    span_hours = max((max(times) - min(times)).total_seconds() / 3600.0, 1 / 60) if times else 1.0

    dst_counts = Counter(e.dst_ip for e in history)
    # Typical = destinations carrying at least 5% of this device's connections.
    typical = [d for d, c in dst_counts.most_common() if c / len(history) >= 0.05]

    baseline = {
        "window": f"last {len(history)} events",
        "avg_bytes_out": round(sum(e.bytes_transferred or 0 for e in history) / len(history), 1),
        "avg_connections": round(len(history) / span_hours, 2),  # per hour
        "typical_destinations": typical[:20],
    }

    unusual = []
    for dst in sorted(alert_dsts - set(typical)):
        evs = [e for e in history if e.dst_ip == dst]
        first = min((_event_time(e) for e in evs if _event_time(e)), default=None)
        unusual.append({
            "destination": dst,
            "first_seen": iso_utc(first),
            "connection_count": len(evs),
            "bytes_out": sum(e.bytes_transferred or 0 for e in evs),
        })

    # Bursts: one-minute buckets with ≥3× the median per-minute connection rate.
    buckets = {}
    for e in history:
        t = _event_time(e)
        if t is None:
            continue
        key = t.replace(second=0, microsecond=0)
        b = buckets.setdefault(key, [0, 0])
        b[0] += 1
        b[1] += e.bytes_transferred or 0
    threshold = max(BURST_MIN_CONNECTIONS, 3 * median(c for c, _ in buckets.values())) if buckets else None
    bursts = [
        {"start": iso_utc(k), "end": iso_utc(k.replace(second=59)), "connection_count": c, "bytes_out": b}
        for k, (c, b) in sorted(buckets.items(), key=lambda kv: kv[1][0], reverse=True)
        if threshold is not None and c >= threshold
    ][:10]

    return baseline, unusual, bursts


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
    # Flows and records only: packets are already inside their flow, and application
    # activity is attributed to users, not to an address.
    events = (
        Event.query
        .filter(Event.src_ip == device_id, Event.event_type.in_(TRAFFIC_EVENT_TYPES))
        .order_by(Event.received_at.desc())
        .limit(limit)
        .all()
    )

    timeline = [e.to_dict() for e in reversed(events)]  # chronological
    device_alerts = Alert.query.filter_by(src_ip=device_id).all()
    baseline, unusual, bursts = _behaviour_profile(device_id, {a.dst_ip for a in device_alerts})

    payload = {
        "device": device.to_dict(),
        "timeline": timeline,
        "event_count": len(events),
        # Dashboard contract
        "device_id": device.device_id,
        "data_source": current_data_source(),
        "events": timeline,
        "baseline": baseline,
        "unusual_destinations": unusual,
        "bursts": bursts,
        "related_alert_ids": [str(a.id) for a in device_alerts],
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
