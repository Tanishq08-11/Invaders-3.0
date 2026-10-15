"""
Configuration — Person 4 Backend
==================================
• PostgreSQL via DATABASE_URL env var (production / hackathon demo).
• Falls back to SQLite for local development.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "insider-threat-ai-secret-key-2026")
    DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    JSON_SORT_KEYS = False

    # Database — PostgreSQL preferred, SQLite fallback
    INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(INSTANCE_DIR, 'insider_threat.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File storage
    DATA_DIR = os.path.join(BASE_DIR, "data")
    CHECKPOINTS_DIR = os.path.join(INSTANCE_DIR, "checkpoints")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(CHECKPOINTS_DIR, exist_ok=True)
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB

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
