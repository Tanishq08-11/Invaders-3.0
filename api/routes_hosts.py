"""
Host Profiles & Insider Threat Leaderboard API Blueprint.
Tracks internal endpoints, cumulative egress volumes, and anomaly histories.
"""
from flask import Blueprint, request, jsonify
from core.database import db
from core.models_db import HostProfile, Alert, FlowRecord

bp_hosts = Blueprint("hosts", __name__, url_prefix="/api/v1/hosts")


@bp_hosts.route("", methods=["GET"])
def list_hosts():
    """
    Returns internal hosts ranked by insider threat risk score and alert count.
    Query param: flagged_only (true/false)
    """
    flagged_only = request.args.get("flagged_only", "false").lower() in ["true", "1"]
    query = HostProfile.query

    if flagged_only:
        query = query.filter_by(is_flagged=True)

    hosts = query.order_by(
        HostProfile.current_risk_score.desc(),
        HostProfile.alert_count.desc()
    ).all()

    return jsonify({
        "total_hosts": len(hosts),
        "hosts": [h.to_dict() for h in hosts]
    })


@bp_hosts.route("/<ip_address>", methods=["GET"])
def get_host_detail(ip_address: str):
    """
    Returns comprehensive forensic profile for a specific host IP,
    including associated alerts and recent encrypted flow events.
    """
    host = HostProfile.query.filter_by(ip_address=ip_address).first()
    if not host:
        return jsonify({"error": f"Host profile for {ip_address} not found"}), 404

    # Related alerts for this host
    alerts = (
        Alert.query.filter_by(src_ip=ip_address)
        .order_by(Alert.timestamp.desc())
        .limit(20)
        .all()
    )

    # Recent flow activity
    recent_flows = (
        FlowRecord.query.filter_by(src_ip=ip_address)
        .order_by(FlowRecord.id.desc())
        .limit(30)
        .all()
    )

    return jsonify({
        "profile": host.to_dict(),
        "alerts_count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
        "recent_flows": [f.to_dict() for f in recent_flows]
    })


@bp_hosts.route("/<ip_address>/flag", methods=["POST"])
def toggle_host_flag(ip_address: str):
    """Flags or unflags a host as a high-risk insider endpoint for quarantine."""
    host = HostProfile.query.filter_by(ip_address=ip_address).first()
    if not host:
        return jsonify({"error": f"Host {ip_address} not found"}), 404

    data = request.get_json() or {}
    flag = data.get("is_flagged", not host.is_flagged)
    host.is_flagged = bool(flag)
    db.session.commit()

    action_text = "quarantined/flagged" if host.is_flagged else "cleared/unflagged"
    return jsonify({
        "message": f"Host {ip_address} {action_text} successfully",
        "host": host.to_dict()
    })
