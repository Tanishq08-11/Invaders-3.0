"""
Flask Application — Person 4 Backend
======================================
Wires together:
  POST /api/v1/events              — ingest events
  GET  /api/v1/alerts              — list alerts (filters: severity, status)
  GET  /api/v1/alerts/{id}         — alert detail + evidence
  PATCH /api/v1/alerts/{id}        — update disposition / status
  GET  /api/v1/devices/{id}/timeline — device activity
  GET  /api/v1/metrics             — model & system evaluation metrics
  GET  /api/v1/health              — service + model availability
  GET  /api/v1/stream/live         — SSE real-time feed

Database: PostgreSQL via DATABASE_URL env var, falls back to SQLite for dev.
AI integration: imports the detector module — never duplicates calculations.
"""
import os
from flask import Flask
from flask_cors import CORS

from config import Config
from core.database import db

# Blueprints
from api.routes_events  import bp_events
from api.routes_alerts  import bp_alerts
from api.routes_devices import bp_devices
from api.routes_metrics import bp_metrics
from api.routes_health  import bp_health
from api.routes_stream  import bp_stream

from services.event_processor import EventProcessor
from services.training_service import TrainingService


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # CORS for Security Dashboard frontend
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Database
    db.init_app(app)

    # Register the exact Person 4 API surface
    app.register_blueprint(bp_events)     # POST /api/v1/events
    app.register_blueprint(bp_alerts)     # GET/PATCH /api/v1/alerts
    app.register_blueprint(bp_devices)    # GET /api/v1/devices/{id}/timeline
    app.register_blueprint(bp_metrics)    # GET /api/v1/metrics
    app.register_blueprint(bp_health)     # GET /api/v1/health
    app.register_blueprint(bp_stream)     # GET /api/v1/stream/live + sim controls

    # Root redirect to health
    @app.route("/", methods=["GET"])
    def root():
        from flask import redirect
        return redirect("/api/v1/health")

    # ------------------------------------------------------------------
    # Bootstrap: create tables + train baseline if first run
    # ------------------------------------------------------------------
    with app.app_context():
        db.create_all()

        checkpoint = os.path.join(Config.CHECKPOINTS_DIR, "kitnet_baseline.pkl")
        normal_csv = os.path.join(Config.DATA_DIR, "botiot_normal_train.csv")

        if not os.path.exists(checkpoint) and os.path.exists(normal_csv):
            print("[Bootstrap] Training KitNET baseline on BoT-IoT normal data…")
            try:
                trainer = TrainingService(checkpoint_path=checkpoint)
                result = trainer.train_baseline_from_csv(normal_csv, epochs=1, max_rows=1200)
                proc = EventProcessor.get_instance()
                proc.reload_model()
                if result.get("model_version_id"):
                    proc.set_active_model_version(result["model_version_id"])
                print(f"[Bootstrap] Done — {result['clusters']} clusters, "
                      f"baseline μ={result['baseline_mean']}")
            except Exception as e:
                print(f"[Bootstrap] Warning: {e}")
        else:
            # Model already trained — just load it
            proc = EventProcessor.get_instance()
            if proc.model_loaded:
                from core.models import ModelVersion
                active = ModelVersion.query.filter_by(is_active=True).first()
                if active:
                    proc.set_active_model_version(active.id)

    return app


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'='*66}")
    print(f"  Insider Threat Detection Backend — Person 4")
    print(f"  Encrypted Traffic Analysis  ·  Zero Decryption  ·  Port {port}")
    print(f"{'='*66}")
    print(f"  POST /api/v1/events              Ingest events")
    print(f"  GET  /api/v1/alerts              List alerts")
    print(f"  GET  /api/v1/alerts/{{id}}         Alert detail + evidence")
    print(f"  PATCH /api/v1/alerts/{{id}}        Update disposition/status")
    print(f"  GET  /api/v1/devices/{{id}}/timeline  Device activity")
    print(f"  GET  /api/v1/metrics             Model & system metrics")
    print(f"  GET  /api/v1/health              Service health check")
    print(f"  GET  /api/v1/stream/live         SSE real-time feed")
    print(f"{'='*66}\n")
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG, threaded=True)
