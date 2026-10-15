"""
Automated Tests for PCAP Endpoint Input Validation
===================================================
Validates:
  • Missing PCAP file rejection (HTTP 400)
  • Unsupported file extension rejection (HTTP 400)
  • Empty file rejection (HTTP 400)
  • Non-integer max_packets rejection (HTTP 400)
  • Zero and negative max_packets rejection (HTTP 400)
  • Excessive max_packets boundary enforcement (HTTP 400)
  • Clean JSON error messages without internal stack trace leaks
"""
import io
import pytest
from app import create_app
from core.database import db
from config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MAX_PCAP_PACKETS = 50000


@pytest.fixture
def client():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()


def test_pcap_missing_file(client):
    """Verifies that requests without a multipart file are rejected with HTTP 400."""
    res = client.post("/api/v1/collector/pcap", data={})
    assert res.status_code == 400
    assert "error" in res.get_json()
    assert "No PCAP file provided" in res.get_json()["error"]


def test_pcap_invalid_extension(client):
    """Verifies that non-pcap files are rejected with HTTP 400."""
    data = {
        "file": (io.BytesIO(b"dummy text content"), "malicious_script.exe")
    }
    res = client.post("/api/v1/collector/pcap", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "error" in res.get_json()
    assert "supported" in res.get_json()["error"].lower()


def test_pcap_empty_file(client):
    """Verifies that 0-byte files are rejected with HTTP 400."""
    data = {
        "file": (io.BytesIO(b""), "empty_capture.pcap")
    }
    res = client.post("/api/v1/collector/pcap", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "error" in res.get_json()
    assert "empty" in res.get_json()["error"].lower()


def test_pcap_invalid_max_packets_string(client):
    """Verifies that non-integer max_packets values (e.g. 'abc') return HTTP 400."""
    data = {
        "file": (io.BytesIO(b"non-empty binary dummy data"), "test.pcap"),
        "max_packets": "abc"
    }
    res = client.post("/api/v1/collector/pcap", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "error" in res.get_json()
    assert "positive integer" in res.get_json()["error"].lower()


def test_pcap_zero_max_packets(client):
    """Verifies that max_packets=0 is rejected with HTTP 400."""
    data = {
        "file": (io.BytesIO(b"non-empty binary dummy data"), "test.pcap"),
        "max_packets": "0"
    }
    res = client.post("/api/v1/collector/pcap", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "error" in res.get_json()
    assert "greater than zero" in res.get_json()["error"].lower()


def test_pcap_negative_max_packets(client):
    """Verifies that negative max_packets is rejected with HTTP 400."""
    data = {
        "file": (io.BytesIO(b"non-empty binary dummy data"), "test.pcap"),
        "max_packets": "-10"
    }
    res = client.post("/api/v1/collector/pcap", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "error" in res.get_json()
    assert "greater than zero" in res.get_json()["error"].lower()


def test_pcap_excessive_max_packets(client):
    """Verifies that max_packets exceeding MAX_PCAP_PACKETS limit is rejected with HTTP 400."""
    data = {
        "file": (io.BytesIO(b"non-empty binary dummy data"), "test.pcap"),
        "max_packets": "9999999"
    }
    res = client.post("/api/v1/collector/pcap", data=data, content_type="multipart/form-data")
    assert res.status_code == 400
    assert "error" in res.get_json()
    assert "exceeds maximum" in res.get_json()["error"].lower()
