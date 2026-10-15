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
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from config import Config
from core.auth import install_soc_guard, seed_accounts
from core.database import db
import core.models  # noqa: F401  — registers every table (incl. users/files) before create_all

# Blueprints
from api.routes_events  import bp_events
from api.routes_alerts  import bp_alerts
from api.routes_devices import bp_devices
from api.routes_metrics import bp_metrics
from api.routes_health  import bp_health
from api.routes_stream  import bp_stream
from api.routes_model   import bp_model
from api.routes_dataset import bp_dataset
from api.routes_collector import bp_collector
from api.routes_auth    import bp_auth
from api.routes_files   import bp_files, bp_employees

from services.event_processor import EventProcessor
from services.training_service import TrainingService


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    if app.config.get("TESTING"):
        # Tests never touch the real users database.
        app.config["SQLALCHEMY_BINDS"] = {"auth": "sqlite:///:memory:"}

    # CORS for Security Dashboard frontend (configurable via CORS_ORIGINS)
    cors_origins = app.config.get("CORS_ORIGINS", "*")
    if isinstance(cors_origins, str) and "," in cors_origins:
        cors_origins = [o.strip() for o in cors_origins.split(",") if o.strip()]
    # Credentials (session cookie) are only allowed with an explicit origin list, never "*".
    CORS(app, resources={r"/api/*": {"origins": cors_origins}},
         supports_credentials=cors_origins != "*")

    # Database
    db.init_app(app)

    # Portal auth: SECURITY_ANALYST session required on every SOC route
    install_soc_guard(app)

    # ------------------------------------------------------------------
    # Canonical Person 4 Route Registration
    # Note: Legacy prototype blueprints (routes_detection.py, routes_hosts.py,
    # and routes_stats.py) are intentionally omitted from registration because
    # they depend on deprecated prototypes (models_db.py) and are superseded
    # by canonical Person 4 blueprints:
    #   • bp_events (replaces bp_detection)
    #   • bp_devices (replaces bp_hosts)
    #   • bp_metrics (replaces bp_stats)
    # ------------------------------------------------------------------
    app.register_blueprint(bp_events)     # POST /api/v1/events
    app.register_blueprint(bp_alerts)     # GET/PATCH /api/v1/alerts
    app.register_blueprint(bp_devices)    # GET /api/v1/devices/{id}/timeline
    app.register_blueprint(bp_metrics)    # GET /api/v1/metrics
    app.register_blueprint(bp_health)     # GET /api/v1/health
    app.register_blueprint(bp_stream)     # GET /api/v1/stream/live + sim controls
    app.register_blueprint(bp_model)      # GET/POST /api/v1/model (train, status, thresholds, verify)
    app.register_blueprint(bp_dataset)    # GET/POST /api/v1/dataset (info, sample, upload)
    app.register_blueprint(bp_collector)  # GET/POST /api/v1/collector (live capture, pcap, status)
    app.register_blueprint(bp_auth)       # POST /api/v1/auth/login|logout, GET /api/v1/auth/me
    app.register_blueprint(bp_files)      # /api/v1/files (employee portal)
    app.register_blueprint(bp_employees)  # GET /api/v1/employees/me

    # JSON errors on /api so the dashboard can show `detail` (e.g. 413 upload too large)
    @app.errorhandler(HTTPException)
    def _http_error(err):
        if request.path.startswith("/api/"):
            return jsonify({"detail": err.description, "error": err.name}), err.code
        return err

    # ------------------------------------------------------------------
    # Frontend: serve the built SPA (frontend/dist) when present;
    # otherwise "/" redirects to the health check as before.
    # ------------------------------------------------------------------
    dist = app.config.get("FRONTEND_DIST")

    @app.route("/", defaults={"path": ""}, methods=["GET"])
    @app.route("/<path:path>", methods=["GET"])
    def frontend(path: str):
        from flask import abort, redirect
        if path.startswith("api/"):
            abort(404)
        if not dist or not os.path.isfile(os.path.join(dist, "index.html")):
            if path == "":
                return redirect("/api/v1/health")
            abort(404)
        if path and os.path.isfile(os.path.join(dist, path)):
            return send_from_directory(dist, path)
        return send_from_directory(dist, "index.html")  # client-side routes

    # ------------------------------------------------------------------
    # Bootstrap: create tables + train baseline if first run
    # ------------------------------------------------------------------
    with app.app_context():
        db.create_all()

        if app.config.get("SEED_DEMO_USERS") and not app.config.get("TESTING"):
            created = seed_accounts(app.config["CREDENTIALS_FILE"])
            if created:
                print(f"[Bootstrap] Created {len(created)} portal accounts in the users database. "
                      f"Credentials written to {app.config['CREDENTIALS_FILE']}")

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
    print(f"  GET/POST /api/v1/collector/*     Live network metadata capture")
    print(f"  POST /api/v1/auth/login|logout   Portal sessions (GET /auth/me)")
    print(f"  /api/v1/files, /employees/me     Employee file portal")
    if os.path.isfile(os.path.join(Config.FRONTEND_DIST, "index.html")):
        print(f"  Dashboard UI                     http://localhost:{port}/")
    else:
        print(f"  Dashboard UI                     not built — run: cd frontend && npm run build")
    print(f"{'='*66}\n")
    app.run(host="0.0.0.0", port=port, debug=Config.DEBUG, threaded=True)
