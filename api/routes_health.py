"""
GET /api/v1/health — check service, database, collector, and model availability.
================================================================================
Returns a structured health payload distinguishing between:
- Backend process availability
- Database connectivity (via actual ping query)
- Collector operational state and mode (live vs. simulation vs. stopped)
- AI model status (without modifying model implementation)
"""
from flask import Blueprint, jsonify
from core.database import db
from services.event_processor import EventProcessor
from services.live_collector import LiveCollector
from core.models import ModelVersion

bp_health = Blueprint("health", __name__, url_prefix="/api/v1")


@bp_health.route("/health", methods=["GET"])
def health_check():
    # 1. Database connectivity check
    db_status = "connected"
    try:
        db.session.execute(db.text("SELECT 1"))
    except Exception:
        db_status = "unavailable"

    # 2. EventProcessor & Model state
    proc = EventProcessor.get_instance()
    model_status = "loaded" if proc.model_loaded else "unavailable"

    # 3. Collector status & operating mode
    collector = LiveCollector.get_instance()
    c_status = collector.get_status()

    # 4. Overall service status
    if db_status != "connected":
        overall = "unhealthy"
    elif not proc.model_loaded:
        overall = "degraded"  # Backend up, but AI model pending teammate delivery
    else:
        overall = "healthy"

    active_model = None
    if db_status == "connected":
        try:
            active_model = ModelVersion.query.filter_by(is_active=True).first()
        except Exception:
            pass

    return jsonify({
        "status":  overall,
        "service": "insider-threat-detection-backend",
        "version": "3.0.0",
        "components": {
            "database":           db_status,
            "model":              model_status,
            "collector":          c_status["mode"],
            "feature_extractor":  "ready",
            "risk_engine":        "ready",
            "explanation_engine": "ready",
        },
        "collector": {
            "is_running":        collector.is_running,
            "mode":              collector.mode,
            "is_live":           collector.mode == "live",
            "is_simulated":      collector.mode == "simulation",
            "packets_captured":  collector.packets_captured,
            "events_ingested":   collector.events_ingested,
            "processing_errors": collector.processing_errors_count,
            "collector_errors":  collector.collector_errors_count,
        },
        "model_info": {
            "version":    active_model.version if active_model else None,
            "trained_at": active_model.trained_at.isoformat() if active_model else None,
            "is_active":  active_model.is_active if active_model else False,
        } if active_model else None,
        "counters": {
            "events_ingested":  proc.events_ingested,
            "alerts_created":   proc.alerts_created,
        },
    })
