"""
Stats & Telemetry API Blueprint for Security Dashboard.
Provides high-level metrics, time-series anomaly charts, and threat distributions.
"""
from flask import Blueprint, jsonify
from sqlalchemy import func
from core.models_db import Alert, FlowRecord, HostProfile, ModelBaseline
from services.detection_service import DetectionService

bp_stats = Blueprint("stats", __name__, url_prefix="/api/v1/stats")


@bp_stats.route("/overview", methods=["GET"])
def get_overview():
    """Returns high-level system telemetry for the Security Dashboard."""
    detection_svc = DetectionService.get_instance()
    
    total_flows = FlowRecord.query.count()
    total_alerts = Alert.query.count()
    open_alerts = Alert.query.filter_by(status="OPEN").count()
    critical_alerts = Alert.query.filter_by(severity="CRITICAL", status="OPEN").count()
    high_alerts = Alert.query.filter_by(severity="HIGH", status="OPEN").count()

    # Recent average anomaly score
    recent_flows = FlowRecord.query.order_by(FlowRecord.id.desc()).limit(100).all()
    avg_score = (
        sum(f.anomaly_score for f in recent_flows) / len(recent_flows)
        if recent_flows else 0.0
    )

    # Determine Global System Threat Level
    if critical_alerts > 0:
        threat_level = "CRITICAL"
        threat_color = "#ef4444"
    elif high_alerts > 0:
        threat_level = "ELEVATED"
        threat_color = "#f97316"
    elif open_alerts > 0:
        threat_level = "MODERATE"
        threat_color = "#eab308"
    else:
        threat_level = "SECURE"
        threat_color = "#10b981"

    # Flagged hosts count
    flagged_hosts_count = HostProfile.query.filter_by(is_flagged=True).count()

    # Active baseline model
    active_model = ModelBaseline.query.filter_by(is_active=True).first()

    return jsonify({
        "total_flows_analyzed": total_flows,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "flagged_insiders": flagged_hosts_count,
        "average_recent_anomaly_score": round(avg_score, 4),
        "threat_level": threat_level,
        "threat_color": threat_color,
        "is_model_trained": detection_svc.is_model_loaded,
        "active_baseline": active_model.to_dict() if active_model else {
            "version": "Not Calibrated",
            "mean_baseline_error": 0.0,
            "training_samples": 0
        }
    })


@bp_stats.route("/timeline", methods=["GET"])
def get_timeline():
    """
    Returns recent time-series flow records with anomaly scores and sizes
    for plotting real-time charts.
    """
    records = FlowRecord.query.order_by(FlowRecord.id.desc()).limit(60).all()
    # Reverse to return chronological order
    records = list(reversed(records))
    return jsonify([r.to_dict() for r in records])


@bp_stats.route("/distribution", methods=["GET"])
def get_distribution():
    """Returns anomaly severity distribution and target port frequency."""
    # Severity distribution
    severity_counts = (
        FlowRecord.query.with_entities(FlowRecord.severity, func.count(FlowRecord.id))
        .group_by(FlowRecord.severity)
        .all()
    )
    sev_map = {sev: count for sev, count in severity_counts}

    # Port distribution for alerts
    port_counts = (
        Alert.query.with_entities(Alert.dst_port, func.count(Alert.id))
        .group_by(Alert.dst_port)
        .order_by(func.count(Alert.id).desc())
        .limit(6)
        .all()
    )
    ports = [{"port": p, "count": c} for p, c in port_counts if p is not None]

    return jsonify({
        "severity_distribution": {
            "NORMAL": sev_map.get("NORMAL", 0),
            "LOW": sev_map.get("LOW", 0),
            "MEDIUM": sev_map.get("MEDIUM", 0),
            "HIGH": sev_map.get("HIGH", 0),
            "CRITICAL": sev_map.get("CRITICAL", 0)
        },
        "top_attack_ports": ports
    })
