"""
Configuration — Person 4 Backend
==================================
• PostgreSQL via DATABASE_URL env var (production / hackathon demo).
• Falls back to SQLite for local development.
"""
import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def _load_secret_key() -> str:
    """SECRET_KEY env var, else a random key generated once and kept in instance/ (gitignored)."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE_DIR, "instance", ".secret_key")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(secrets.token_hex(32))
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


class Config:
    # Flask — signs the session cookie, so it must never be a value committed to the repo.
    SECRET_KEY = _load_secret_key()
    DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")
    JSON_SORT_KEYS = False
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")

    # Session cookie (portal login). Set SESSION_COOKIE_SECURE=true when served over HTTPS.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "yes")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.environ.get("SESSION_HOURS", 8)))

    # SOC routes require a SECURITY_ANALYST session. POST /api/v1/events (ingestion) stays open.
    SOC_AUTH_REQUIRED = os.environ.get("SOC_AUTH_REQUIRED", "True").lower() in ("true", "1", "yes")

    # Portal accounts (20 workers + 2 analysts) are created on first start when the users
    # database is empty; their random passwords are written once to CREDENTIALS_FILE.
    SEED_DEMO_USERS = os.environ.get("SEED_DEMO_USERS", "True").lower() in ("true", "1", "yes")
    CREDENTIALS_FILE = os.path.join(BASE_DIR, "instance", "worker_credentials.csv")

    # Built frontend (frontend/dist) is served by Flask when present.
    FRONTEND_DIST = os.path.join(BASE_DIR, "frontend", "dist")

    # Database — PostgreSQL preferred, SQLite fallback
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(INSTANCE_DIR, 'insider_threat.db')}"
    )
    # Separate database for portal accounts and the employee file portal
    SQLALCHEMY_BINDS = {
        "auth": os.environ.get(
            "AUTH_DATABASE_URL",
            f"sqlite:///{os.path.join(INSTANCE_DIR, 'veylix_users.db')}"
        ),
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File storage & Upload Limits
    DATA_DIR = os.path.join(BASE_DIR, "data")
    CHECKPOINTS_DIR = os.path.join(INSTANCE_DIR, "checkpoints")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CHECKPOINTS_DIR, exist_ok=True)
    UPLOAD_DIR = os.path.join(INSTANCE_DIR, "uploads")  # employee portal files
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB max upload
    MAX_PCAP_PACKETS = int(os.environ.get("MAX_PCAP_PACKETS", 50000))

    # Kitsune AfterImage lambdas (temporal decay windows)
    AFTERIMAGE_LAMBDAS = [5.0, 3.0, 1.0, 0.1, 0.01]

    # KitNET architecture
    KITNET_GRACE_FEATURE_MAPPING = 300
    KITNET_GRACE_TRAINING = 1200
    KITNET_MAX_CLUSTER_SIZE = 10
    KITNET_HIDDEN_RATIO = 0.75
    KITNET_LEARNING_RATE = 0.05

    # Risk Engine Z-score thresholds
    Z_THRESHOLD_LOW      = 2.0
    Z_THRESHOLD_MEDIUM   = 3.5
    Z_THRESHOLD_HIGH     = 5.5
    Z_THRESHOLD_CRITICAL = 8.5

    # Exfiltration heuristics
    SUSPICIOUS_OUTBOUND_PORTS = [443, 8443, 22, 2222, 8080, 53, 9001, 4444]
    OFF_HOURS_START = 20
    OFF_HOURS_END   = 6

    # ------------------------------------------------------------------
    # Detector boundary
    #   kitnet_baseline — the AfterImage(100-D) → KitNET baseline already in this repo.
    #                     It is NOT the teammate's final model; health reports final_model=false.
    #   none            — no inference: events are stored with detection_status="unavailable".
    # ------------------------------------------------------------------
    DETECTOR_BACKEND = os.environ.get("DETECTOR_BACKEND", "kitnet_baseline").strip().lower()

    # POST /api/v1/events (external ingestion). When set, callers must send X-Ingest-Key
    # (or hold an ADMIN session). Empty = open, which health reports as "open".
    INGEST_API_KEY = os.environ.get("INGEST_API_KEY", "")

    # ------------------------------------------------------------------
    # Network collector
    # ------------------------------------------------------------------
    # Comma-separated interface names an operator may capture on. Empty = any interface
    # Scapy reports. Only list interfaces whose traffic you are authorised to monitor.
    COLLECTOR_ALLOWED_INTERFACES = [
        i.strip() for i in os.environ.get("COLLECTOR_ALLOWED_INTERFACES", "").split(",") if i.strip()
    ]
    # Persist one network_packet event per observed packet (the existing per-packet
    # detector path consumes these). Flows are always aggregated.
    COLLECTOR_PACKET_EVENTS = os.environ.get("COLLECTOR_PACKET_EVENTS", "True").lower() in ("true", "1", "yes")
    COLLECTOR_QUEUE_SIZE = int(os.environ.get("COLLECTOR_QUEUE_SIZE", 5000))
    COLLECTOR_START_TIMEOUT_S = float(os.environ.get("COLLECTOR_START_TIMEOUT_S", 3.0))

    # Flow aggregation (bidirectional 5-tuple flows)
    FLOW_IDLE_TIMEOUT_S = float(os.environ.get("FLOW_IDLE_TIMEOUT_S", 30))
    FLOW_ACTIVE_TIMEOUT_S = float(os.environ.get("FLOW_ACTIVE_TIMEOUT_S", 300))
    FLOW_MAX_TRACKED = int(os.environ.get("FLOW_MAX_TRACKED", 10000))

    # Organisation address space for direction/external classification is read from
    # INTERNAL_NETWORKS (comma-separated CIDRs) in services/network_metadata.py.

    # Optional Zeek TLS enrichment for PCAP analysis (binary path or name on PATH).
    ZEEK_BIN = os.environ.get("ZEEK_BIN", "zeek")
    ZEEK_TIMEOUT_S = int(os.environ.get("ZEEK_TIMEOUT_S", 120))

    # ------------------------------------------------------------------
    # Application ↔ network correlation
    # ------------------------------------------------------------------
    CORRELATION_WINDOW_S = float(os.environ.get("CORRELATION_WINDOW_S", 120))
    # TCP ports the portal itself is served on (connections to these carry portal requests).
    APP_SERVER_PORTS = [
        int(p) for p in os.environ.get("APP_SERVER_PORTS", os.environ.get("PORT", "5000")).split(",") if p.strip().isdigit()
    ]
    # Low-confidence "same client address, close in time, external destination" links.
    # Only recorded when exactly one portal user was seen on that address recently.
    CORRELATION_ADDRESS_PROXIMITY = os.environ.get("CORRELATION_ADDRESS_PROXIMITY", "True").lower() in ("true", "1", "yes")
    CORRELATION_ADDRESS_LOOKBACK_S = float(os.environ.get("CORRELATION_ADDRESS_LOOKBACK_S", 3600))
    CORRELATION_MAX_LINKS_PER_EVENT = int(os.environ.get("CORRELATION_MAX_LINKS_PER_EVENT", 20))

    # Server-Sent Events
    SSE_MAX_SUBSCRIBERS = int(os.environ.get("SSE_MAX_SUBSCRIBERS", 50))
    SSE_HEARTBEAT_S = float(os.environ.get("SSE_HEARTBEAT_S", 15))
