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
from flask import Blueprint, jsonify
from sqlalchemy import func
from core.models import Alert, Event, Device, ModelVersion
from services.event_processor import EventProcessor

bp_metrics = Blueprint("metrics", __name__, url_prefix="/api/v1/metrics")


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
    severity_dist = {sev: cnt for sev, cnt in severity_rows}

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
        "kitnet_phase":    proc.kitnet.phase,
        "input_dimension": proc.kitnet.input_dim,
        "num_clusters":    len(proc.kitnet.clusters),
        "baseline_mean":   round(proc.kitnet.baseline_mean, 6),
        "baseline_std":    round(proc.kitnet.baseline_std, 6),
        "baseline_max":    round(proc.kitnet.baseline_max, 6),
        "thresholds": {
            "z_low":  proc.risk_engine.z_low,
            "z_med":  proc.risk_engine.z_med,
            "z_high": proc.risk_engine.z_high,
            "z_crit": proc.risk_engine.z_crit,
        },
    }

    return jsonify({
        "system":      system,
        "database":    db_counters,
        "model":       model_info,
        "evaluation":  evaluation,
        "severity_distribution": severity_dist,
        "devices":     device_summary,
    })
