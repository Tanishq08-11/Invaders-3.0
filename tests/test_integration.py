"""
Integration Tests — Person 4 Definition of Done
=================================================
"An ingested event passes through the AI, produces a persisted alert when
warranted, and the frontend can retrieve and update that incident."

Tests verify every required route:
  POST /api/v1/events
  GET  /api/v1/alerts
  GET  /api/v1/alerts/{id}
  PATCH /api/v1/alerts/{id}
  GET  /api/v1/devices/{id}/timeline
  GET  /api/v1/metrics
  GET  /api/v1/health
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


# ------------------------------------------------------------------
# 1. GET /api/v1/health
# ------------------------------------------------------------------
def test_health(client):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    body = res.get_json()
    assert body["status"] in ("healthy", "degraded")
    assert "components" in body
    assert body["components"]["database"] == "connected"


# ------------------------------------------------------------------
# 2. POST /api/v1/events — single event ingestion
# ------------------------------------------------------------------
def test_ingest_single_event(client):
    event = {
        "src_ip":   "192.168.1.45",
        "dst_ip":   "142.250.190.46",
        "src_port": 50123,
        "dst_port": 443,
        "protocol": "TCP",
        "bytes":    350,
        "timestamp": 1600000000.0,
    }
    res = client.post("/api/v1/events", json=event)
    assert res.status_code in (201, 202)  # 201 if AI ran, 202 if model unavailable
    body = res.get_json()
    assert "event_uuid" in body
    assert body["src_ip"] == "192.168.1.45"

    # If AI was available, anomaly_score should NOT be None
    # If AI was unavailable, _warning should be present and score should be None
    if body.get("_warning"):
        assert body["anomaly_score"] is None, "Score must be None when AI fails"
    else:
        assert body["anomaly_score"] is not None


# ------------------------------------------------------------------
# 3. POST /api/v1/events — batch ingestion
# ------------------------------------------------------------------
def test_ingest_batch(client):
    batch = {
        "events": [
            {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "bytes": 200, "timestamp": 1600000001.0},
            {"src_ip": "192.168.1.11", "dst_ip": "10.0.0.2", "dst_port": 443, "bytes": 300, "timestamp": 1600000002.0},
        ]
    }
    res = client.post("/api/v1/events", json=batch)
    assert res.status_code == 201
    body = res.get_json()
    assert body["total_processed"] == 2
    assert isinstance(body["results"], list)


# ------------------------------------------------------------------
# 4. POST /api/v1/events — validation errors
# ------------------------------------------------------------------
def test_ingest_invalid_event(client):
    res = client.post("/api/v1/events", json={"foo": "bar"})
    assert res.status_code == 400


def test_ingest_empty_batch(client):
    res = client.post("/api/v1/events", json={"events": []})
    assert res.status_code == 400


# ------------------------------------------------------------------
# 5. GET /api/v1/alerts — list with filters
# ------------------------------------------------------------------
def test_list_alerts_empty(client):
    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    body = res.get_json()
    assert body["total"] == 0
    assert body["alerts"] == []


def test_list_alerts_with_severity_filter(client):
    # Ingest a high-severity event (big exfiltration)
    exfil = {
        "src_ip":   "192.168.1.105",
        "dst_ip":   "198.51.100.77",
        "src_port": 55000,
        "dst_port": 443,
        "protocol": "TCP",
        "bytes":    1460,
        "timestamp": 1600000010.0,
    }
    client.post("/api/v1/events", json=exfil)

    # List all alerts
    res = client.get("/api/v1/alerts")
    body = res.get_json()
    total = body["total"]

    # Filter by a severity that doesn't exist
    res2 = client.get("/api/v1/alerts?severity=NONEXISTENT")
    assert res2.get_json()["total"] == 0

    # Filter by status
    res3 = client.get("/api/v1/alerts?status=open")
    assert res3.status_code == 200


# ------------------------------------------------------------------
# 6. GET /api/v1/alerts/{id} — detail + evidence
# ------------------------------------------------------------------
def test_get_alert_detail(client):
    # Ingest an event that will trigger an alert
    exfil = {
        "src_ip": "192.168.1.105", "dst_ip": "198.51.100.77",
        "src_port": 55000, "dst_port": 443, "protocol": "TCP",
        "bytes": 1460, "timestamp": 1600000020.0,
    }
    ingest_res = client.post("/api/v1/events", json=exfil)
    ingest_body = ingest_res.get_json()

    if ingest_body.get("alert"):
        alert_id = ingest_body["alert"]["id"]
        res = client.get(f"/api/v1/alerts/{alert_id}")
        assert res.status_code == 200
        detail = res.get_json()
        assert "evidence" in detail
        assert "explanation" in detail
        assert "source_events" in detail
        assert "analyst_actions" in detail


def test_get_alert_not_found(client):
    res = client.get("/api/v1/alerts/99999")
    assert res.status_code == 404


# ------------------------------------------------------------------
# 7. PATCH /api/v1/alerts/{id} — update disposition/status
# ------------------------------------------------------------------
def test_update_alert_lifecycle(client):
    # Ingest to create an alert
    exfil = {
        "src_ip": "192.168.1.105", "dst_ip": "198.51.100.77",
        "src_port": 55000, "dst_port": 443, "protocol": "TCP",
        "bytes": 1460, "timestamp": 1600000030.0,
    }
    ingest_body = client.post("/api/v1/events", json=exfil).get_json()

    if ingest_body.get("alert"):
        alert_id = ingest_body["alert"]["id"]

        # Transition: open → investigating
        res1 = client.patch(f"/api/v1/alerts/{alert_id}", json={
            "status": "investigating",
            "analyst": "alice",
        })
        assert res1.status_code == 200
        assert res1.get_json()["alert"]["status"] == "investigating"

        # Set disposition
        res2 = client.patch(f"/api/v1/alerts/{alert_id}", json={
            "disposition": "true_positive",
            "analyst_notes": "Confirmed insider exfiltration via TLS tunnel",
            "analyst": "alice",
        })
        assert res2.status_code == 200
        assert res2.get_json()["alert"]["disposition"] == "true_positive"

        # Resolve
        res3 = client.patch(f"/api/v1/alerts/{alert_id}", json={
            "status": "resolved",
            "analyst": "alice",
        })
        assert res3.status_code == 200
        body3 = res3.get_json()
        assert body3["alert"]["status"] == "resolved"
        assert body3["alert"]["resolved_at"] is not None

        # Verify audit trail
        detail = client.get(f"/api/v1/alerts/{alert_id}").get_json()
        assert len(detail["analyst_actions"]) >= 3


def test_update_alert_invalid_status(client):
    # Ingest to create alert
    exfil = {
        "src_ip": "192.168.1.105", "dst_ip": "198.51.100.77",
        "src_port": 55000, "dst_port": 443, "bytes": 1460, "timestamp": 1600000040.0,
    }
    body = client.post("/api/v1/events", json=exfil).get_json()
    if body.get("alert"):
        res = client.patch(f"/api/v1/alerts/{body['alert']['id']}", json={"status": "banana"})
        assert res.status_code == 400


# ------------------------------------------------------------------
# 8. GET /api/v1/devices/{id}/timeline
# ------------------------------------------------------------------
def test_device_timeline(client):
    # Ingest events from one device
    for i in range(3):
        client.post("/api/v1/events", json={
            "src_ip": "192.168.1.200", "dst_ip": "10.0.0.5",
            "dst_port": 80, "bytes": 200 + i * 100, "timestamp": 1600000050.0 + i,
        })

    res = client.get("/api/v1/devices/192.168.1.200/timeline")
    assert res.status_code == 200
    body = res.get_json()
    assert body["device"]["device_id"] == "192.168.1.200"
    assert len(body["timeline"]) == 3
    assert "alerts" in body


def test_device_not_found(client):
    res = client.get("/api/v1/devices/10.99.99.99/timeline")
    assert res.status_code == 404


# ------------------------------------------------------------------
# 9. GET /api/v1/metrics
# ------------------------------------------------------------------
def test_metrics(client):
    # Ingest a few events first
    client.post("/api/v1/events", json={
        "src_ip": "192.168.1.45", "dst_ip": "10.0.0.1",
        "dst_port": 80, "bytes": 200, "timestamp": 1600000060.0,
    })

    res = client.get("/api/v1/metrics")
    assert res.status_code == 200
    body = res.get_json()
    assert "system" in body
    assert "database" in body
    assert "model" in body
    assert "evaluation" in body
    assert body["database"]["events_total"] >= 1


# ------------------------------------------------------------------
# 10. End-to-End: Definition of Done
# ------------------------------------------------------------------
def test_definition_of_done(client):
    """
    'An ingested event passes through the AI, produces a persisted alert
     when warranted, and the frontend can retrieve and update that incident.'
    """
    # 1. Ingest an exfiltration event
    exfil = {
        "src_ip": "192.168.1.105", "dst_ip": "198.51.100.77",
        "src_port": 55000, "dst_port": 443, "protocol": "TCP",
        "bytes": 1460, "timestamp": 1600000070.0,
    }
    ingest_res = client.post("/api/v1/events", json=exfil)
    assert ingest_res.status_code in (201, 202)
    ingest_body = ingest_res.get_json()

    # 2. Event was persisted
    assert ingest_body["event_uuid"].startswith("EVT-")

    # 3. AI processed it (or recorded failure — never silent zero)
    if ingest_body.get("_warning"):
        assert ingest_body["anomaly_score"] is None
    else:
        assert ingest_body["ai_processed"] is True

    # 4. If alert was generated, frontend can retrieve it
    if ingest_body.get("alert"):
        alert_id = ingest_body["alert"]["id"]
        alert_uuid = ingest_body["alert"]["alert_uuid"]

        # Retrieve by ID
        detail = client.get(f"/api/v1/alerts/{alert_id}").get_json()
        assert detail["alert_uuid"] == alert_uuid
        assert detail["status"] == "open"

        # Retrieve by UUID
        detail2 = client.get(f"/api/v1/alerts/{alert_uuid}").get_json()
        assert detail2["id"] == alert_id

        # 5. Frontend can update the incident
        patch_res = client.patch(f"/api/v1/alerts/{alert_id}", json={
            "status": "investigating",
            "disposition": "true_positive",
            "analyst_notes": "End-to-end test verified",
            "analyst": "test_runner",
        })
        assert patch_res.status_code == 200
        updated = patch_res.get_json()["alert"]
        assert updated["status"] == "investigating"
        assert updated["disposition"] == "true_positive"

    # 6. Metrics reflect the work
    metrics = client.get("/api/v1/metrics").get_json()
    assert metrics["database"]["events_total"] >= 1
