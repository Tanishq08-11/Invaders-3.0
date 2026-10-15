"""
GET /api/v1/health — check whether the service and model are available.
========================================================================
Returns a structured health payload so monitoring tools and the frontend
can determine at a glance whether the backend is operational.
"""
from flask import Blueprint, jsonify
from services.event_processor import EventProcessor
from core.models import ModelVersion

bp_health = Blueprint("health", __name__, url_prefix="/api/v1")


@bp_health.route("/health", methods=["GET"])
def health_check():
    proc = EventProcessor.get_instance()
    active_model = ModelVersion.query.filter_by(is_active=True).first()

    model_status = "loaded" if proc.model_loaded else "unavailable"

    # Overall status: "healthy" only when model is loaded
    overall = "healthy" if proc.model_loaded else "degraded"

    return jsonify({
        "status":  overall,
        "service": "insider-threat-detection-backend",
        "version": "3.0.0",
        "components": {
            "database": "connected",   # if we got here the DB works
            "model":    model_status,
            "feature_extractor": "ready",
            "risk_engine":       "ready",
            "explanation_engine": "ready",
        },
        "model_info": {
            "version":   active_model.version if active_model else None,
            "trained_at": active_model.trained_at.isoformat() if active_model else None,
            "is_active": active_model.is_active if active_model else False,
        } if active_model else None,
        "counters": {
            "events_ingested":  proc.events_ingested,
            "alerts_created":   proc.alerts_created,
        },
    })
