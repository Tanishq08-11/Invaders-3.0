"""
Configuration — Person 4 Backend
==================================
• PostgreSQL via DATABASE_URL env var (production / hackathon demo).
• Falls back to SQLite for local development.
"""
import os
import secrets
from datetime import timedelta


def _env_float(name, default):
    return float(os.environ.get(name, default))


def _env_int(name, default):
    return int(os.environ.get(name, default))


def _env_bool(name, default):
    return os.environ.get(name, str(default)).lower() in ("true", "1", "yes")

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
    #   kitnet_trustlab — the authoritative pre-trained TrustLab KitNET bundle
    #                     (ml/kitnet_trustlab_bundle.pkl, 78 features). Never retrained here.
    #   none            — no inference: events are stored with detection_status="unavailable".
    # The retired AfterImage(100-D) bootstrap baseline is NOT a selectable backend: if the
    # bundle cannot be loaded, detection is reported unavailable — there is no fallback.
    # ------------------------------------------------------------------
    DETECTOR_BACKEND = os.environ.get("DETECTOR_BACKEND", "kitnet_trustlab").strip().lower()
    TRUSTLAB_BUNDLE_PATH = os.environ.get("TRUSTLAB_BUNDLE_PATH", os.path.join(BASE_DIR, "ml", "kitnet_trustlab_bundle.pkl"))
    # Integrity guard: a bundle with a different schema/threshold is refused, not silently used.
    TRUSTLAB_EXPECTED_FEATURES = 78
    TRUSTLAB_EXPECTED_THRESHOLD = 0.07018400015809657
    # Timezone of the HourSin/HourCos/DaySin/DayCos model inputs (defaults to DETECTION_TIMEZONE).
    TRUSTLAB_TIMEZONE = os.environ.get("TRUSTLAB_TIMEZONE", os.environ.get("DETECTION_TIMEZONE", "UTC"))
    # An event is only scored when at least this many of the 74 flow features (excluding
    # ports/protocol) were measured; otherwise it would be scored on training medians.
    TRUSTLAB_MIN_MEASURED_FEATURES = int(os.environ.get("TRUSTLAB_MIN_MEASURED_FEATURES", 20))
    # Which observed port fills "Src Port" / "Dst Port" for aggregated flows.
    #   service_src  Src Port = responder (service) port, Dst Port = initiator (client) port.
    #                Matches the bundle's own training medians (Src Port 1131, Dst Port 44590.5).
    #   initiator    Src Port = initiator port (CICFlowMeter's usual orientation).
    # Fwd/Bwd statistics stay initiator→responder in both modes. Records keep their own columns.
    TRUSTLAB_PORT_ORIENTATION = os.environ.get("TRUSTLAB_PORT_ORIENTATION", "service_src").strip().lower()

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

    # ------------------------------------------------------------------
    # Rule-based detection layer (services/detection/) — independent of the AI model.
    # Every threshold below is a documented policy default; override per environment.
    # ------------------------------------------------------------------
    DETECTION_ENABLED = _env_bool("DETECTION_ENABLED", True)
    DETECTORS_DISABLED = [d.strip().upper() for d in os.environ.get("DETECTORS_DISABLED", "").split(",") if d.strip()]
    DETECTION_TIMEZONE = os.environ.get("DETECTION_TIMEZONE", "UTC")       # D4 hour-of-day profiles
    RULE_ALERT_MIN_SCORE = _env_float("RULE_ALERT_MIN_SCORE", 60)          # combined rule score for an alert
    DETECTION_SIGNAL_RETENTION_DAYS = _env_float("DETECTION_SIGNAL_RETENTION_DAYS", 180)

    # Baselines
    BASELINE_MIN_SAMPLES = _env_int("BASELINE_MIN_SAMPLES", 20)
    BASELINE_WINDOW_DAYS = _env_float("BASELINE_WINDOW_DAYS", 30)
    BASELINE_MAX_SAMPLES = _env_int("BASELINE_MAX_SAMPLES", 500)
    BASELINE_RETENTION_DAYS = _env_float("BASELINE_RETENTION_DAYS", 90)
    ROBUST_Z_THRESHOLD = _env_float("ROBUST_Z_THRESHOLD", 6.0)            # robust z (median/MAD) to trigger

    # D1 large upload / D5 upload-heavy / D6 long upload
    D1_MIN_OUTBOUND_BYTES = _env_int("D1_MIN_OUTBOUND_BYTES", 10 * 1024 * 1024)
    D1_HIGH_OUTBOUND_BYTES = _env_int("D1_HIGH_OUTBOUND_BYTES", 500 * 1024 * 1024)
    D5_MIN_OUTBOUND_BYTES = _env_int("D5_MIN_OUTBOUND_BYTES", 1024 * 1024)
    D5_MIN_LOG2_RATIO = _env_float("D5_MIN_LOG2_RATIO", 3.0)              # 8:1 upload:download
    D6_MIN_DURATION_S = _env_float("D6_MIN_DURATION_S", 240)
    D6_MIN_OUTBOUND_BYTES = _env_int("D6_MIN_OUTBOUND_BYTES", 20 * 1024 * 1024)
    # D2 destination novelty
    D2_MIN_ORG_FLOWS = _env_int("D2_MIN_ORG_FLOWS", 200)                   # org history before novelty counts
    D2_MIN_OUTBOUND_BYTES = _env_int("D2_MIN_OUTBOUND_BYTES", 1024 * 1024)
    # D4 unusual time
    D4_MIN_ACTIVE_HOURS = _env_int("D4_MIN_ACTIVE_HOURS", 40)
    D4_MIN_DAYS = _env_int("D4_MIN_DAYS", 7)
    D4_RARE_FRACTION = _env_float("D4_RARE_FRACTION", 0.02)
    # D7 slow leak (hourly CUSUM over EWMA baseline)
    D7_BUCKET_S = _env_int("D7_BUCKET_S", 3600)
    D7_MIN_BUCKETS = _env_int("D7_MIN_BUCKETS", 48)
    D7_EWMA_ALPHA = _env_float("D7_EWMA_ALPHA", 0.05)
    D7_CUSUM_K = _env_float("D7_CUSUM_K", 0.5)
    D7_CUSUM_H = _env_float("D7_CUSUM_H", 8.0)
    D7_MAX_GAP_BUCKETS = _env_int("D7_MAX_GAP_BUCKETS", 48)
    # D8 automated transfer
    D8_MIN_PACKETS = _env_int("D8_MIN_PACKETS", 30)
    D8_MIN_OUTBOUND_BYTES = _env_int("D8_MIN_OUTBOUND_BYTES", 1024 * 1024)
    D8_MAX_IAT_ENTROPY = _env_float("D8_MAX_IAT_ENTROPY", 0.35)
    D8_MAX_IAT_CV = _env_float("D8_MAX_IAT_CV", 0.5)
    # D9 spread-out leaking / D10 behaviour change (daily rollups)
    D9_MIN_BYTES_PER_DEST = _env_int("D9_MIN_BYTES_PER_DEST", 256 * 1024)
    D9_MIN_DESTINATIONS = _env_int("D9_MIN_DESTINATIONS", 5)
    D9_MIN_DAYS = _env_int("D9_MIN_DAYS", 7)
    D10_MIN_DAYS = _env_int("D10_MIN_DAYS", 7)
    D10_Z = _env_float("D10_Z", 4.0)
    # D16 internal bulk download
    D16_WINDOW_S = _env_int("D16_WINDOW_S", 3600)
    D16_MIN_FILES = _env_int("D16_MIN_FILES", 20)
    D16_MIN_BYTES = _env_int("D16_MIN_BYTES", 200 * 1024 * 1024)
    D16_MIN_WINDOWS = _env_int("D16_MIN_WINDOWS", 10)
    D16_POLICY_MAX_FILES = _env_int("D16_POLICY_MAX_FILES", 200)            # absolute policy ceiling
    # D17 DNS tunnelling
    D17_WINDOW_S = _env_int("D17_WINDOW_S", 600)
    D17_MIN_SUBDOMAINS = _env_int("D17_MIN_SUBDOMAINS", 30)
    D17_MIN_LABEL_LEN = _env_float("D17_MIN_LABEL_LEN", 24)
    D17_MIN_LABEL_ENTROPY = _env_float("D17_MIN_LABEL_ENTROPY", 3.5)
    # D19 beaconing
    D19_MIN_INTERVALS = _env_int("D19_MIN_INTERVALS", 8)
    D19_MAX_REL_DISPERSION = _env_float("D19_MAX_REL_DISPERSION", 0.1)
    D19_MIN_INTERVAL_S = _env_float("D19_MIN_INTERVAL_S", 10)
    D19_MAX_INTERVAL_S = _env_float("D19_MAX_INTERVAL_S", 6 * 3600)
    # D21 protocol novelty / D28 lateral movement / D22 connection failures
    D21_MIN_ENTITY_FLOWS = _env_int("D21_MIN_ENTITY_FLOWS", 100)
    D21_COMMON_MIN_ENTITIES = _env_int("D21_COMMON_MIN_ENTITIES", 3)
    D22_WINDOW_S = _env_int("D22_WINDOW_S", 600)
    D22_MIN_FAILURES = _env_int("D22_MIN_FAILURES", 20)
    D22_SCAN_DISTINCT_TARGETS = _env_int("D22_SCAN_DISTINCT_TARGETS", 50)
    D28_WINDOW_S = _env_int("D28_WINDOW_S", 900)
    D28_MIN_NEW_HOSTS = _env_int("D28_MIN_NEW_HOSTS", 5)
    D28_MIN_HISTORY_FLOWS = _env_int("D28_MIN_HISTORY_FLOWS", 100)
    # D13/D14/D27 sessions & authentication
    D13_OVERLAP_GRACE_S = _env_float("D13_OVERLAP_GRACE_S", 300)
    D14_MIN_LOGINS = _env_int("D14_MIN_LOGINS", 10)
    D27_WINDOW_S = _env_int("D27_WINDOW_S", 900)
    D27_ACCOUNT_FAILURES = _env_int("D27_ACCOUNT_FAILURES", 5)
    D27_SPRAY_ACCOUNTS = _env_int("D27_SPRAY_ACCOUNTS", 5)
    # D15 two devices / D11 heartbeat / D24 multi-stage / D26 TLS fingerprint
    D15_WINDOW_S = _env_int("D15_WINDOW_S", 600)
    D24_WINDOW_S = _env_int("D24_WINDOW_S", 86400)
    D24_MIN_STAGES = _env_int("D24_MIN_STAGES", 3)
    D26_MIN_OBSERVATIONS = _env_int("D26_MIN_OBSERVATIONS", 10)
    TELEMETRY_SWEEP_S = _env_int("TELEMETRY_SWEEP_S", 60)              # sweep interval (D11/D25); min 10 s
    DETECTION_SWEEP_ENABLED = _env_bool("DETECTION_SWEEP_ENABLED", True)   # background scheduler (off under TESTING)
    D25_MAX_DROP_RATIO = _env_float("D25_MAX_DROP_RATIO", 0.01)
    D25_MAX_OUTBOX_PENDING = _env_int("D25_MAX_OUTBOX_PENDING", 50)

    # Optional enrichment data sources (local files only; see services/detection/enrichment.py)
    GEOIP_COUNTRY_DB = os.environ.get("GEOIP_COUNTRY_DB", "")
    GEOIP_CITY_DB = os.environ.get("GEOIP_CITY_DB", "")
    GEOIP_ASN_DB = os.environ.get("GEOIP_ASN_DB", "")
    THREAT_INTEL_DIR = os.environ.get("THREAT_INTEL_DIR", os.path.join(BASE_DIR, "instance", "intel"))
    INTEL_MAX_AGE_DAYS = _env_float("INTEL_MAX_AGE_DAYS", 7)
    POLICY_FILE = os.environ.get("POLICY_FILE", os.path.join(BASE_DIR, "policies", "destination_policy.json"))
    # Heartbeat telemetry ingestion (POST /api/v1/telemetry/heartbeat) uses INGEST_API_KEY.
