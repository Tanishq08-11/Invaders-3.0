"""
GET /api/v1/health — actual state of every pipeline stage.
===========================================================
Public (it is the dashboard's connection probe), but only SOC viewers (analyst/admin,
or SOC auth disabled in development) receive the detailed sections; everyone else gets
the overall status and component states without counters or interface names.

Each capability is reported on its own — nothing is "healthy" by association:
  database        ping query
  detector        ready | unavailable | disabled — and final_model=false: the bundled
                  KitNET baseline is a prototype, not the teammate's final model
  collector       stopped | starting | live | simulation | failed, plus whether live capture
                  is possible on this host and whether it has actually been started
  tls             built-in handshake parser (SNI/JA3), JA4 unsupported, Zeek presence
  sse             current live-update subscribers
  ingestion_auth  whether POST /api/v1/events requires a key
"""
from flask import Blueprint, current_app, jsonify

from core.auth import is_soc_viewer
from core.database import db
from core.data_source import current_data_source
from core.models import Event, ModelVersion, iso_utc
from services import app_activity
from services.event_processor import EventProcessor
from services.live_collector import LiveCollector

bp_health = Blueprint("health", __name__, url_prefix="/api/v1")


@bp_health.route("/health", methods=["GET"])
def health_check():
    db_status = "connected"
    try:
        db.session.execute(db.text("SELECT 1"))
    except Exception:
        db.session.rollback()
        db_status = "unavailable"

    proc = EventProcessor.get_instance()
    detector = proc.detector_status()
    collector = LiveCollector.get_instance()
    c_status = collector.get_status()

    if db_status != "connected":
        overall = "unhealthy"
    elif not detector["available"]:
        overall = "degraded"  # events are stored and shown, but nothing is scored
    else:
        overall = "healthy"

    base = {
        "status": overall,
        "service": "insider-threat-detection-backend",
        "version": "3.1.0",
        "database": db_status,
        "model_loaded": detector["available"],
        "detector_state": detector["state"],
        "components": {
            "database":  db_status,
            "detector":  detector["state"],
            "model":     "loaded" if detector["available"] else "unavailable",
            "collector": c_status["mode"],
        },
    }
    if not is_soc_viewer():
        return jsonify(base)

    active_model = None
    last_event_at = None
    pending_app_events = None
    if db_status == "connected":
        try:
            active_model = ModelVersion.query.filter_by(is_active=True).first()
            last_event_at = iso_utc(db.session.query(db.func.max(Event.received_at)).scalar())
            pending_app_events = app_activity.pending_count()
        except Exception:
            db.session.rollback()

    base["components"].update({
        "feature_extractor":  "ready" if detector["available"] else "idle",
        "risk_engine":        "ready" if detector["available"] else "idle",
        "explanation_engine": "ready" if detector["available"] else "idle",
        "tls_enrichment":     "builtin" + ("+zeek" if c_status["tls"]["zeek"]["available"] else ""),
        "live_capture":       ("verified" if c_status["live_capture_verified"] else "not_started")
                              if c_status["live_capture_available"] else "unavailable",
    })
    base.update({
        "detector": detector,
        "collector": {
            "mode":                   c_status["mode"],
            "is_running":             c_status["is_running"],
            "is_live":                c_status["is_live"],
            "is_simulated":           c_status["is_simulated"],
            "active_interface":       c_status["active_interface"],
            "live_capture_available": c_status["live_capture_available"],
            "live_capture_unavailable_reason": c_status["live_capture_unavailable_reason"],
            "live_capture_verified":  c_status["live_capture_verified"],
            "packets_captured":       c_status["packets_captured"],
            "packets_dropped":        c_status["packets_dropped"],
            "events_ingested":        c_status["events_ingested"],
            "flows_completed":        c_status["flows_completed"],
            "active_flows":           c_status["active_flows"],
            "processing_errors":      c_status["processing_errors"],
            "collector_errors":       c_status["collector_errors"],
            "last_collector_error":   c_status["last_collector_error"],
        },
        "tls": c_status["tls"],
        "sse": {"subscribers": proc.subscriber_count,
                "max_subscribers": current_app.config.get("SSE_MAX_SUBSCRIBERS")},
        "ingestion_auth": "api_key" if current_app.config.get("INGEST_API_KEY") else "open",
        "application_events_pending": pending_app_events,
        "model_info": {
            "version":    active_model.version,
            "trained_at": iso_utc(active_model.trained_at),
            "is_active":  active_model.is_active,
        } if active_model else None,
        "counters": proc.counters(),
        # Dashboard contract
        "model_version": active_model.version if active_model else None,
        "ingestion":     c_status["mode"] if c_status["is_running"] else "idle",
        "last_event_at": last_event_at,
        "data_source":   current_data_source(),
    })
    return jsonify(base)
