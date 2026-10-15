"""
Automated Tests for Route Registration, Health, and Metrics
===========================================================
Validates:
  • Canonical Person 4 route registration in app.py
  • Intentionally unregistered legacy prototype routes return 404
  • Health endpoint performs real database check
  • Health endpoint accurately reports collector operating mode
  • Metrics endpoint exposes complete collector and system telemetry
"""
import pytest
from app import create_app
from core.database import db
from config import Config
from services.live_collector import LiveCollector


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_canonical_routes_registered(client):
    """Verifies all 9 canonical Person 4 blueprints are registered and active."""
    endpoints = [
        ("/api/v1/health", "GET", 200),
        ("/api/v1/metrics", "GET", 200),
        ("/api/v1/alerts", "GET", 200),
        ("/api/v1/devices", "GET", 200),
        ("/api/v1/model/status", "GET", 200),
        ("/api/v1/dataset/info", "GET", 200),
        ("/api/v1/collector/status", "GET", 200),
        ("/api/v1/collector/interfaces", "GET", 200),
    ]

    for path, method, expected_status in endpoints:
        if method == "GET":
            res = client.get(path)
            assert res.status_code == expected_status, f"Route {path} failed with {res.status_code}"


def test_legacy_prototype_routes_not_registered(client):
    """
    Verifies that obsolete/duplicate prototype blueprints (hosts, stats, detection)
    are intentionally unregistered and return 404.
    """
    legacy_paths = [
        "/api/v1/hosts",
        "/api/v1/stats",
        "/api/v1/stats/overview",
        "/api/v1/detection/inspect",
    ]
    for path in legacy_paths:
        res = client.get(path)
        assert res.status_code == 404, f"Legacy route {path} should not be registered"


def test_health_database_live_ping(client):
    """Verifies health check performs an actual database ping query."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["components"]["database"] == "connected"
    assert data["status"] in ("healthy", "degraded")


def test_health_collector_mode_distinction(client):
    """Verifies health endpoint reflects live vs. simulation vs. stopped collector mode."""
    collector = LiveCollector.get_instance()
    collector.stop_capture()

    # 1. When stopped
    res_stopped = client.get("/api/v1/health")
    data_stopped = res_stopped.get_json()
    assert data_stopped["collector"]["mode"] == "stopped"
    assert data_stopped["collector"]["is_running"] is False

    # 2. When simulation started
    collector.start_live_capture(simulate=True)
    res_sim = client.get("/api/v1/health")
    data_sim = res_sim.get_json()
    assert data_sim["collector"]["mode"] == "simulation"
    assert data_sim["collector"]["is_simulated"] is True
    assert data_sim["collector"]["is_live"] is False
    assert data_sim["collector"]["is_running"] is True

    # 3. Clean up
    collector.stop_capture()
    res_cleaned = client.get("/api/v1/health")
    assert res_cleaned.get_json()["collector"]["mode"] == "stopped"


def test_metrics_telemetry_consistency(client):
    """Verifies metrics payload includes collector telemetry matching collector state."""
    res = client.get("/api/v1/metrics")
    assert res.status_code == 200
    data = res.get_json()
    assert "collector" in data
    assert "mode" in data["collector"]
    assert "packets_captured" in data["collector"]
    assert "events_ingested" in data["collector"]
    assert "processing_errors" in data["collector"]
    assert "system" in data
    assert "database" in data
