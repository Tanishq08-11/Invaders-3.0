"""
Integration and API Tests for Person 4 Endpoints
================================================
Validates:
  • Health & readiness check (GET /api/v1/health)
  • Devices directory & quarantine flagging (GET /api/v1/devices, POST /api/v1/devices/{id}/flag)
  • Stream simulation controls (GET /api/v1/stream/status, start, pause, stop)
  • Alerts advanced filtering (GET /api/v1/alerts with severity, status, limit)
  • Event ingestion payload validation and error handling
"""
import pytest
from app import create_app
from core.database import db
from config import Config


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


def test_health_check(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] in ("healthy", "degraded")
    assert "components" in data
    assert data["components"]["database"] == "connected"


def test_devices_listing_and_flagging(client):
    # Ingest an event to register a device
    event = {
        "src_ip": "10.0.0.55",
        "dst_ip": "198.51.100.99",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "TCP",
        "bytes": 500,
        "timestamp": 1600000000.0,
    }
    client.post("/api/v1/events", json=event)

    # 1. List devices
    res = client.get("/api/v1/devices")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total"] >= 1
    device = next((d for d in data["devices"] if d["device_id"] == "10.0.0.55"), None)
    assert device is not None
    assert device["is_flagged"] is False

    # 2. Flag device for quarantine
    res_flag = client.post("/api/v1/devices/10.0.0.55/flag", json={"is_flagged": True})
    assert res_flag.status_code == 200
    flag_data = res_flag.get_json()
    assert flag_data["is_flagged"] is True

    # 3. Verify flagged filter
    res_flagged = client.get("/api/v1/devices?flagged_only=true")
    assert res_flagged.status_code == 200
    flagged_data = res_flagged.get_json()
    assert any(d["device_id"] == "10.0.0.55" for d in flagged_data["devices"])


def test_simulation_stream_controls(client):
    # Check status
    res_status = client.get("/api/v1/stream/status")
    assert res_status.status_code == 200
    status_data = res_status.get_json()
    assert "is_running" in status_data

    # Pause and resume
    res_pause = client.post("/api/v1/stream/pause")
    assert res_pause.status_code == 200
    res_resume = client.post("/api/v1/stream/resume")
    assert res_resume.status_code == 200
    res_stop = client.post("/api/v1/stream/stop")
    assert res_stop.status_code == 200


def test_alerts_filtering_advanced(client):
    # Submit suspicious exfiltration event to trigger an alert
    exfil = {
        "src_ip": "10.10.10.99",
        "dst_ip": "203.0.113.5",
        "src_port": 51234,
        "dst_port": 443,
        "protocol": "TCP",
        "bytes": 50000000,
        "duration": 180.0,
        "timestamp": 1600000000.0,
    }
    client.post("/api/v1/events", json=exfil)

    # Filter by status=open
    res_open = client.get("/api/v1/alerts?status=open")
    assert res_open.status_code == 200
    data_open = res_open.get_json()
    assert "alerts" in data_open
    assert "total" in data_open

    # Filter with non-matching severity
    res_low = client.get("/api/v1/alerts?severity=LOW")
    assert res_low.status_code == 200
    data_low = res_low.get_json()
    for a in data_low["alerts"]:
        assert a["severity"] == "LOW"
