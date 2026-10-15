"""
GET /api/v1/metrics — serve model and system evaluation metrics.
================================================================
Returns two categories of metrics:

1. **System metrics** — operational counters the backend tracks in-memory:
   events ingested, events evaluated, AI failures, alerts created.

2. **Model metrics** — the active KitNET baseline calibration parameters
   and, when analyst dispositions are available, precision / false-positive
   rate estimates.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify
from sqlalchemy import func
from core.data_source import current_data_source
from core.models import Alert, Event, Device, ModelVersion, iso_utc
from services.event_processor import EventProcessor

bp_metrics = Blueprint("metrics", __name__, url_prefix="/api/v1/metrics")

TREND_EVENTS = 5000   # most recent events summarised into the traffic trend
TREND_BUCKETS = 24


def _traffic_trend():
    """Outbound bytes, event count and alert-raising events over the recent event window."""
    rows = (
        Event.query
        .with_entities(Event.received_at, Event.bytes_transferred, Event.alert_id)
        .order_by(Event.received_at.desc())
        .limit(TREND_EVENTS)
        .all()
    )
    rows = [r for r in rows if r.received_at is not None]
    if not rows:
        return []
    start = min(r.received_at for r in rows)
    span = max((max(r.received_at for r in rows) - start).total_seconds(), 60.0)
    width = span / TREND_BUCKETS
    buckets = [{"bytes_out": 0, "events": 0, "anomalies": 0} for _ in range(TREND_BUCKETS)]
    for r in rows:
        i = min(int((r.received_at - start).total_seconds() / width), TREND_BUCKETS - 1)
        buckets[i]["bytes_out"] += r.bytes_transferred or 0
        buckets[i]["events"] += 1
        buckets[i]["anomalies"] += 1 if r.alert_id else 0
    return [
        {"timestamp": iso_utc(start + timedelta(seconds=i * width)), **b}
        for i, b in enumerate(buckets)
    ]


@bp_metrics.route("", methods=["GET"])
def get_metrics():
    proc = EventProcessor.get_instance()

    # --- system counters (in-memory, fast) ---
    system = {
        "events_ingested":  proc.events_ingested,
        "events_evaluated": proc.events_evaluated,
        "events_failed":    proc.events_failed,
        "alerts_created":   proc.alerts_created,
        "model_loaded":     proc.model_loaded,
    }

    # --- database counters (ground truth) ---
    db_events_total = Event.query.count()
    db_events_ok    = Event.query.filter_by(ai_processed=True).count()
    db_events_err   = Event.query.filter(Event.ai_error.isnot(None)).count()
    db_alerts_total = Alert.query.count()
    db_alerts_open  = Alert.query.filter_by(status="open").count()

    db_counters = {
        "events_total":   db_events_total,
        "events_ok":      db_events_ok,
        "events_errored": db_events_err,
        "alerts_total":   db_alerts_total,
        "alerts_open":    db_alerts_open,
    }

    # --- severity distribution ---
    severity_rows = (
        Alert.query
        .with_entities(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    severity_dist = {str(sev).lower(): cnt for sev, cnt in severity_rows}

    # --- analyst disposition distribution (for precision estimates) ---
    disp_rows = (
        Alert.query
        .filter(Alert.disposition.isnot(None))
        .with_entities(Alert.disposition, func.count(Alert.id))
        .group_by(Alert.disposition)
        .all()
    )
    disposition_dist = {d: c for d, c in disp_rows}

    tp = disposition_dist.get("true_positive", 0) + proc.true_positives
    fp = disposition_dist.get("false_positive", 0) + proc.false_positives
    reviewed = tp + fp
    precision = round(tp / reviewed, 4) if reviewed > 0 else None
    fp_rate   = round(fp / reviewed, 4) if reviewed > 0 else None

    evaluation = {
        "true_positives":  tp,
        "false_positives": fp,
        "reviewed":        reviewed,
        "precision":       precision,
        "false_positive_rate": fp_rate,
        "dispositions":    disposition_dist,
    }

    # --- device summary ---
    flagged_count = Device.query.filter_by(is_flagged=True).count()
    device_summary = {
        "total_tracked": Device.query.count(),
        "flagged":       flagged_count,
    }

    # --- model version ---
    active_model = ModelVersion.query.filter_by(is_active=True).first()

    model_info = {
        "active_version":  active_model.to_dict() if active_model else None,
        "kitnet_phase":    getattr(proc.kitnet, "phase", "active") if proc.kitnet else "unavailable",
        "input_dimension": getattr(proc.kitnet, "input_dim", 100) if proc.kitnet else 0,
        "num_clusters":    len(getattr(proc.kitnet, "clusters", [])) if proc.kitnet else 0,
        "baseline_mean":   round(getattr(proc.kitnet, "baseline_mean", 0.0), 6) if proc.kitnet else 0.0,
        "baseline_std":    round(getattr(proc.kitnet, "baseline_std", 1.0), 6) if proc.kitnet else 0.0,
        "baseline_max":    round(getattr(proc.kitnet, "baseline_max", 10.0), 6) if proc.kitnet else 0.0,
        "thresholds": {
            "z_low":  proc.risk_engine.z_low,
            "z_med":  proc.risk_engine.z_med,
            "z_high": proc.risk_engine.z_high,
            "z_crit": proc.risk_engine.z_crit,
        } if proc.risk_engine else None,
    }

    # --- collector telemetry ---
    from services.live_collector import LiveCollector
    collector = LiveCollector.get_instance()
    collector_metrics = collector.get_status()

    return jsonify({
        "system":      system,
        "database":    db_counters,
        "collector":   collector_metrics,
        "model":       model_info,
        "evaluation":  evaluation,
        "severity_distribution": severity_dist,
        "devices":     device_summary,
        # Dashboard KPI contract
        "monitored_devices":    device_summary["total_tracked"],
        "observed_events":      db_events_total,
        "open_incidents":       Alert.query.filter(Alert.status.in_(("open", "investigating"))).count(),
        "high_priority_alerts": Alert.query.filter(
            Alert.status.in_(("open", "investigating")),
            Alert.severity.in_(("HIGH", "CRITICAL")),
        ).count(),
        "traffic_trend": _traffic_trend(),
        "data_source":   current_data_source(),
        "generated_at":  iso_utc(datetime.now(timezone.utc)),
    })
