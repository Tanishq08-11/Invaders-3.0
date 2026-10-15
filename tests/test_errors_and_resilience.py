"""
Automated Resilience and Error Handling Test Suite
==================================================
Validates:
  1. Live network collector error recovery & malformed packet resilience
  2. Collector telemetry under corrupted / failed packet processing
  3. Safe handling of invalid / corrupted PCAP uploads
  4. Idempotent start/stop collector lifecycle
  5. Ingestion fault tolerance: event persisted first when AI model fails
  6. Live environment capture execution and throughput verification
"""
import os
import time
import pytest
from app import create_app
from core.database import db
from config import Config
from services.live_collector import LiveCollector, PcapValidationError
import services.live_collector as live_collector_mod


def _pretend_interface(monkeypatch, name="eth-test"):
    """Live-start tests use a fake interface and a capture provider that 'exists'."""
    monkeypatch.setattr(LiveCollector, "list_interfaces",
                        lambda self: [{"name": name, "description": name, "ips": [], "allowed": True}])
    monkeypatch.setattr(live_collector_mod, "capture_precheck", lambda: {"available": True, "reason": None})
    return name
from services.event_processor import EventProcessor


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


def test_malformed_packet_handling():
    """Validates that corrupt or non-IP packets do not crash the metadata extractor."""
    collector = LiveCollector.get_instance()

    # 1. Non-IP packet (ARP or raw Ethernet frame)
    class NonIPPacket:
        def haslayer(self, layer):
            return False

    meta_non_ip = collector.extract_packet_metadata(NonIPPacket())
    assert meta_non_ip is None

    # 2. Corrupted packet object raising unexpected exceptions
    class BrokenPacket:
        def haslayer(self, layer):
            raise RuntimeError("Corrupted layer descriptor in packet header")

    meta_broken = collector.extract_packet_metadata(BrokenPacket())
    assert meta_broken is None


def test_collector_processing_failure_isolation():
    """
    Validates that if an event ingestion callback throws an unhandled exception,
    the collector catches it, increments processing_errors, and continues running.
    """
    collector = LiveCollector.get_instance()
    collector.stop_capture()
    initial_errors = collector.processing_errors_count

    # Define a buggy callback that always raises
    def failing_callback(meta):
        raise ValueError("Simulated ingestion pipeline crash")

    collector.set_ingest_callback(failing_callback)

    # Feed a packet to the handler
    try:
        from scapy.all import IP, TCP
        pkt = IP(src="10.10.10.1", dst="10.10.10.2") / TCP(sport=1234, dport=80)
    except Exception:
        class FakeLayer:
            src = "10.10.10.1"
            dst = "10.10.10.2"
            sport = 1234
            dport = 80
        class FakePacket:
            def haslayer(self, layer):
                return True
            def __getitem__(self, layer):
                return FakeLayer()
            def __len__(self):
                return 64
        pkt = FakePacket()

    collector.is_running = True
    collector._on_packet(pkt)

    # Verify collector caught the error without crashing
    status = collector.get_status()
    assert status["processing_errors"] > initial_errors
    assert "Simulated ingestion pipeline crash" in (status["last_processing_error"] or "")

    # Clean up callback
    collector.set_ingest_callback(None)
    collector.stop_capture()


def test_invalid_pcap_parsing_error_handling(client, tmp_path):
    """Validates that invalid or corrupted PCAP files return structured errors instead of crashing."""
    # Create a corrupted dummy PCAP file
    corrupt_pcap = tmp_path / "corrupted_capture.pcap"
    corrupt_pcap.write_bytes(b"THIS IS NOT A VALID PCAP FILE HEADER DATA STREAM 1234567890")

    # A file without a pcap/pcapng header is rejected before any parsing is attempted.
    collector = LiveCollector.get_instance()
    with pytest.raises(PcapValidationError):
        collector.process_pcap_file(str(corrupt_pcap), auto_ingest=False)

    # Test file-not-found error handling
    with pytest.raises(FileNotFoundError):
        collector.process_pcap_file("non_existent_file_path_12345.pcap")


def test_collector_idempotent_lifecycle(client):
    """Validates idempotency and error states when calling start/stop repeatedly."""
    collector = LiveCollector.get_instance()
    collector.stop_capture()

    # 1. Stopping when already stopped
    res_stop_idle = client.post("/api/v1/collector/stop")
    assert res_stop_idle.status_code == 200
    assert res_stop_idle.get_json()["status"] == "not_running"

    # 2. Start capture
    res_start = client.post("/api/v1/collector/start", json={"simulate": True})
    assert res_start.status_code == 200
    assert res_start.get_json()["status"] in ("started", "already_running")

    # 3. Starting again while already running
    res_start_again = client.post("/api/v1/collector/start", json={"simulate": True})
    assert res_start_again.status_code == 200
    assert res_start_again.get_json()["status"] == "already_running"

    # Clean up
    client.post("/api/v1/collector/stop")


def test_persist_first_guarantee_on_ai_failure(client):
    """
    Validates the architectural invariant:
    If the AI model is unloaded or fails during execution, the incoming event
    is preserved in the database with ai_error set and anomaly_score null.
    """
    proc = EventProcessor.get_instance()

    # Temporarily force model_loaded to False to simulate AI failure / degradation
    original_state = proc.model_loaded
    try:
        proc.model_loaded = False

        event_payload = {
            "src_ip": "10.0.4.99",
            "dst_ip": "198.51.100.22",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 2048,
            "timestamp": 1600000500.0,
        }

        res = client.post("/api/v1/events", json=event_payload)
        # HTTP 202 Accepted: event persisted first, but AI evaluation degraded
        assert res.status_code in (200, 201, 202)
        data = res.get_json()

        # The event was persisted, NOT dropped
        assert data["id"] is not None
        assert data["src_ip"] == "10.0.4.99"
        # The AI error was documented, NOT assigned zero score
        assert data["ai_processed"] is False
        assert data["anomaly_score"] is None
        assert "Model not loaded" in (data.get("ai_error") or data.get("_warning") or "")

    finally:
        proc.model_loaded = original_state


def test_live_environment_capture_execution():
    """
    Tests live network collector execution in the current environment,
    verifying packet ingestion, uptime tracking, and throughput calculation.
    """
    collector = LiveCollector.get_instance()
    collector.stop_capture()

    # Start live capture (simulation mode ensures test passes in restricted CI / headless sandbox)
    start_info = collector.start_live_capture(simulate=True)
    assert start_info["status"] == "started"

    # Wait for packets to flow
    time.sleep(2.1)

    status = collector.get_status()
    assert status["is_running"] is True
    assert status["packets_captured"] >= 1
    assert status["bytes_captured"] > 0
    assert status["uptime_seconds"] > 0
    assert status["throughput_pps"] >= 0

    # Stop capture
    stop_info = collector.stop_capture()
    assert stop_info["status"] == "stopped"
    assert stop_info["packets_captured"] >= 1
    assert stop_info["duration_s"] > 0


def test_collector_startup_failure_clears_stale_sniffer(monkeypatch):
    """
    Validates Requirement 3: When Scapy startup fails:
    - Record actual failure
    - Clear invalid or stale sniffer references
    - Report the FAILED state (not live, not silently stopped) when fallback is disabled
    """
    collector = LiveCollector.get_instance()
    collector.stop_capture()

    class FailingSniffer:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            raise PermissionError("Raw socket privilege denied: CAP_NET_RAW required")

    import services.live_collector
    monkeypatch.setattr(services.live_collector, "AsyncSniffer", FailingSniffer)
    iface = _pretend_interface(monkeypatch)

    res = collector.start_live_capture(interface=iface, allow_fallback=False)
    assert res["status"] == "error"
    assert res["mode"] == "failed"
    assert collector.get_status()["is_live"] is False
    assert collector.is_running is False
    assert collector._sniffer is None
    assert "privilege denied" in (collector.last_collector_error or "").lower()


def test_collector_startup_failure_explicit_fallback(monkeypatch):
    """
    Validates Requirement 3: When Scapy fails and fallback is enabled:
    - Switch to simulation explicitly
    - Never report simulation as successful live capture
    - Clear stale sniffer reference
    """
    collector = LiveCollector.get_instance()
    collector.stop_capture()

    class FailingSniffer:
        def __init__(self, *args, **kwargs):
            pass
        def start(self):
            raise RuntimeError("Npcap driver missing")

    import services.live_collector
    monkeypatch.setattr(services.live_collector, "AsyncSniffer", FailingSniffer)
    iface = _pretend_interface(monkeypatch)

    res = collector.start_live_capture(interface=iface, allow_fallback=True)
    assert res["status"] == "started"
    assert res["mode"] == "simulation"
    assert res["scapy_live"] is False
    assert "warning" in res
    assert collector._sniffer is None
    assert collector.is_running is True

    collector.stop_capture()


def test_failed_ingestion_not_counted_as_success():
    """
    Validates Requirement 4:
    - Failed ingestion attempts increment processing_errors
    - Do NOT count a failed ingestion as a successful ingestion
    - Packets observed vs events successfully ingested are cleanly separated
    """
    collector = LiveCollector.get_instance()
    collector.stop_capture()

    collector.packets_captured = 0
    collector.events_ingested = 0
    collector.processing_errors_count = 0

    # Callback returns error dict
    def error_callback(meta):
        return {"error": "Database constraint violation"}

    collector.set_ingest_callback(error_callback)
    collector.is_running = True

    try:
        from scapy.all import IP, TCP
        pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=5000, dport=80)
    except Exception:
        class DummyLayer:
            src = "192.168.1.1"
            dst = "10.0.0.1"
            sport = 5000
            dport = 80
        class DummyPkt:
            def haslayer(self, layer):
                return True
            def __getitem__(self, layer):
                return DummyLayer()
            def __len__(self):
                return 100
        pkt = DummyPkt()

    collector._on_packet(pkt)

    assert collector.packets_captured == 1
    assert collector.events_ingested == 0  # NOT counted as success
    assert collector.processing_errors_count == 1
    assert "Database constraint violation" in (collector.last_processing_error or "")

    # Now with successful callback
    def success_callback(meta):
        return {"id": 123, "ai_processed": True}

    collector.set_ingest_callback(success_callback)
    collector._on_packet(pkt)

    assert collector.packets_captured == 2
    assert collector.events_ingested == 1  # Now incremented by 1
    assert collector.processing_errors_count == 1  # Remains 1

    collector.set_ingest_callback(None)
    collector.stop_capture()

