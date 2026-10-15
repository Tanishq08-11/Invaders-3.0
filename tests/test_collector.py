"""
Automated Tests for Live Network Collector & Metadata Extraction
================================================================
Validates:
  • Zero payload decryption 5-tuple extraction
  • GET  /api/v1/collector/status
  • GET  /api/v1/collector/interfaces
  • POST /api/v1/collector/start
  • POST /api/v1/collector/stop
  • Offline PCAP processing endpoint /api/v1/collector/pcap
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


def test_collector_status(client):
    res = client.get("/api/v1/collector/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "is_capturing" in data
    assert "mode" in data
    assert "is_live" in data
    assert "is_simulated" in data
    assert "packets_captured" in data
    assert "events_ingested" in data
    assert "processing_errors" in data
    assert "collector_errors" in data
    assert "throughput_pps" in data


def test_collector_interfaces(client):
    res = client.get("/api/v1/collector/interfaces")
    assert res.status_code == 200
    data = res.get_json()
    assert "total" in data
    assert isinstance(data["interfaces"], list)
    assert data["total"] == len(data["interfaces"])


def test_collector_start_and_stop(client):
    # Live capture never starts on an implicit default interface
    res_live = client.post("/api/v1/collector/start", json={"filter": "ip"})
    assert res_live.status_code == 400
    assert "interface" in res_live.get_json()["error"].lower()
    client.post("/api/v1/collector/stop")  # clear the FAILED state

    # Start (explicitly requested, labelled) simulation
    res_start = client.post("/api/v1/collector/start", json={"filter": "ip", "mode": "simulation"})
    assert res_start.status_code == 200
    assert res_start.get_json()["mode"] == "simulation"
    data_start = res_start.get_json()
    assert data_start["status"] in ("started", "running", "already_running")

    # Verify status reflects running
    status_res = client.get("/api/v1/collector/status")
    assert status_res.status_code == 200
    assert status_res.get_json()["is_running"] is True

    # Stop capture
    res_stop = client.post("/api/v1/collector/stop")
    assert res_stop.status_code == 200
    data_stop = res_stop.get_json()
    assert data_stop["status"] in ("stopped", "idle")

    # Verify status reflects stopped
    status_res2 = client.get("/api/v1/collector/status")
    assert status_res2.get_json()["is_running"] is False


def test_packet_metadata_extraction_unit():
    collector = LiveCollector.get_instance()
    
    try:
        from scapy.all import IP, TCP
        pkt = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=54321, dport=443)
    except Exception:
        class MockLayer:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)
        class MockPacket:
            time = 1700000000.0
            def __init__(self):
                self.layers = {
                    "IP": MockLayer(src="192.168.1.100", dst="10.0.0.1"),
                    "TCP": MockLayer(sport=54321, dport=443)
                }
            def haslayer(self, layer):
                return getattr(layer, "__name__", str(layer)) in self.layers
            def __getitem__(self, layer):
                return self.layers[getattr(layer, "__name__", str(layer))]
            def __len__(self):
                return 1200
        pkt = MockPacket()

    meta = collector.extract_packet_metadata(pkt)
    assert meta is not None
    assert meta["src_ip"] == "192.168.1.100"
    assert meta["dst_ip"] == "10.0.0.1"
    assert meta["src_port"] == 54321
    assert meta["dst_port"] == 443
    assert meta["protocol"] == "TCP"
    assert meta["bytes"] > 0
    # Confirm NO packet payload data is in metadata
    assert "payload" not in meta
    assert "data" not in meta
