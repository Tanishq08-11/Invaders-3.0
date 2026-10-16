"""
Integration tests for the unified event pipeline:
application activity → events (outbox), network packets/flows → events, correlation,
detector-unavailable behaviour, collector modes, PCAP analysis, access control, health,
SSE and schema migration.

Tests marked MOCKED replace the detector with a stub to exercise the software interface
only; they say nothing about detection accuracy.
"""
import io
import json
import sqlite3
import threading
import time

import pytest
from werkzeug.security import generate_password_hash

import services.live_collector as live_collector_mod
from app import create_app
from config import Config
from core.database import db
from core.models import (
    ROLE_ADMIN, ROLE_ANALYST, ROLE_EMPLOYEE, Alert, Event, EventCorrelation, FileActivity, StoredFile, User,
)
from net_builders import tls_session
from services import app_activity
from services.event_processor import EventProcessor
from services.live_collector import LiveCollector

PASSWORD = "correct horse battery"


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    APP_SERVER_PORTS = [5000]
    INGEST_API_KEY = ""


@pytest.fixture
def app(tmp_path):
    app = create_app(TestConfig)
    app.config["SOC_AUTH_REQUIRED"] = True
    app.config["UPLOAD_DIR"] = str(tmp_path / "uploads")
    app.config["INSTANCE_DIR"] = str(tmp_path)
    with app.app_context():
        db.create_all()
        fast = lambda: generate_password_hash(PASSWORD, method="pbkdf2:sha256:1000")  # noqa: E731
        db.session.add_all([
            User(username="eng01", password_hash=fast(), display_name="Eng One", role=ROLE_EMPLOYEE, department="Engineering"),
            User(username="eng02", password_hash=fast(), display_name="Eng Two", role=ROLE_EMPLOYEE, department="Engineering"),
            User(username="analyst01", password_hash=fast(), display_name="Analyst", role=ROLE_ANALYST, department="SOC"),
            User(username="admin01", password_hash=fast(), display_name="Admin", role=ROLE_ADMIN, department="SOC"),
            StoredFile(name="Engineering Shared", kind="folder", department="Engineering"),
        ])
        db.session.commit()
        yield app
        LiveCollector.get_instance().set_ingest_callback(None)
        LiveCollector.get_instance().stop_capture()
        db.session.remove()
        db.drop_all()


@pytest.fixture
def proc():
    return EventProcessor.get_instance()


def login(app, username, remote="10.0.0.5"):
    c = app.test_client()
    c.environ_base["REMOTE_ADDR"] = remote
    assert c.post("/api/v1/auth/login", json={"username": username, "password": PASSWORD}).status_code == 200
    return c


def upload(client, content=b"quarterly numbers", name="report.xlsx"):
    return client.post("/api/v1/files", data={"file": (io.BytesIO(content), name)}, content_type="multipart/form-data")


def flow(src, dst, sport, dport, start, end, fwd, bwd, proto="TCP"):
    return {
        "event_type": "network_flow", "flow_id": f"F{src}{sport}{dst}{dport}{start}".replace(".", ""),
        "timestamp": start, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
        "protocol": proto, "bytes": fwd + bwd, "pkts": 4, "duration": end - start,
        "details": {"start_time": start, "end_time": end, "fwd_bytes": fwd, "bwd_bytes": bwd,
                    "fwd_packets": 2, "bwd_packets": 2, "total_packets": 4, "end_reason": "tcp_close"},
    }


def store_flow(proc, f, source="live_capture"):
    return proc.submit(f, event_type="network_flow", source=source, dedup_key=f"flow:{f['flow_id']}")


# ======================================================================= application activity
def test_upload_and_download_record_activity_and_security_events(app):
    eng = login(app, "eng01")
    res = upload(eng)
    assert res.status_code == 201
    file_id = res.get_json()["id"]
    assert eng.get(f"/api/v1/files/{file_id}/download").status_code == 200

    with app.app_context():
        acts = FileActivity.query.order_by(FileActivity.id).all()
        assert [(a.action, a.result) for a in acts] == [("upload", "success"), ("download", "success")]
        assert all(a.security_event_status == "recorded" and a.security_event_payload is None for a in acts)
        events = Event.query.filter_by(event_type="application_activity").order_by(Event.id).all()
        assert len(events) == 2  # exactly one event per activity — no duplicates
        up = events[0]
        user = User.query.filter_by(username="eng01").first()
        assert up.user_id == user.id and up.action == "upload" and up.outcome == "success"
        assert up.src_ip == "10.0.0.5" and up.dst_ip is None and up.device_id is None
        assert up.detection_status == "not_applicable" and up.anomaly_score is None
        assert up.details["file_id"] == file_id and up.details["size_bytes"] == len(b"quarterly numbers")
        # Neither the file name, nor contents, nor storage path is in the security event
        blob = json.dumps(up.to_dict())
        assert "report.xlsx" not in blob and "quarterly" not in blob and "uploads" not in blob
        assert acts[0].security_event_uuid == up.event_uuid

    # The employee still sees their own activity log as before
    items = eng.get("/api/v1/files/activity").get_json()["items"]
    assert {(i["action"], i["result"]) for i in items} == {("upload", "success"), ("download", "success")}

    # Analysts see the application events in the event log, with the authenticated user
    analyst = login(app, "analyst01")
    log = analyst.get("/api/v1/events?type=application_activity").get_json()["items"]
    assert len(log) == 2 and log[0]["user"]["username"] == "eng01"


def test_denied_and_failed_operations_are_recorded(app):
    eng, other = login(app, "eng01"), login(app, "eng02", remote="10.0.0.6")
    item = upload(eng, b"private", "mine.txt").get_json()
    assert other.get(f"/api/v1/files/{item['id']}/download").status_code == 403
    with app.app_context():
        denied = Event.query.filter_by(event_type="application_activity", outcome="denied").one()
        assert denied.user_id == User.query.filter_by(username="eng02").first().id
        u = User.query.filter_by(username="eng01").first()
        u.storage_quota_bytes = 1
        db.session.commit()
    assert upload(eng, b"too big").status_code == 413
    with app.app_context():
        failed = Event.query.filter_by(action="upload", outcome="failed").one()
        assert failed.details["size_bytes"] == len(b"too big")


def test_soc_database_failure_keeps_activity_and_retries(app, proc, monkeypatch):
    eng = login(app, "eng01")
    original = proc.record_application_activity
    monkeypatch.setattr(proc, "record_application_activity", lambda **kw: {"error": "Event could not be stored (database error)."})
    assert upload(eng).status_code == 201  # the file operation itself succeeds
    with app.app_context():
        act = FileActivity.query.one()
        assert act.security_event_status == "failed" and act.security_event_payload
        assert Event.query.filter_by(event_type="application_activity").count() == 0
    monkeypatch.setattr(proc, "record_application_activity", original)
    with app.app_context():
        assert app_activity.retry_pending() == {"attempted": 1, "recorded": 1}
        assert FileActivity.query.one().security_event_status == "recorded"
        assert Event.query.filter_by(event_type="application_activity").count() == 1
        assert app_activity.retry_pending() == {"attempted": 0, "recorded": 0}


def test_application_event_is_idempotent(app, proc):
    with app.app_context():
        kw = dict(activity_id=77, user_id=1, action="download", outcome="success",
                  occurred_at=None, client_ip="10.0.0.5", context={"size_bytes": 10})
        first = proc.record_application_activity(**kw)
        second = proc.record_application_activity(**kw)
        assert second["duplicate"] is True and second["event_uuid"] == first["event_uuid"]
        assert Event.query.filter_by(dedup_key="file_activity:77").count() == 1


# ======================================================================= detector boundary
def test_detector_unavailable_events_still_stored_and_listed(app, proc, monkeypatch):
    monkeypatch.setattr(proc, "model_loaded", False)
    c = app.test_client()
    res = c.post("/api/v1/events", json={"src_ip": "10.0.4.99", "dst_ip": "45.33.32.156", "dst_port": 443, "bytes": 9000})
    assert res.status_code == 202
    body = res.get_json()
    assert body["detection_status"] == "unavailable" and body["anomaly_score"] is None and body["alert"] is None
    analyst = login(app, "analyst01")
    items = analyst.get("/api/v1/events?type=network_record").get_json()["items"]
    assert items[0]["detection_status"] == "unavailable" and items[0]["anomaly_score"] is None
    with app.app_context():
        assert Alert.query.count() == 0  # no fabricated AI alert


def test_detector_disabled_is_reported_everywhere(app, proc, monkeypatch):
    monkeypatch.setattr(proc, "detector_backend", "none")
    with app.app_context():
        r = proc.ingest({"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1"})
        assert r["detection_status"] == "unavailable" and "disabled" in r["_warning"].lower()
    analyst = login(app, "analyst01")
    h = analyst.get("/api/v1/health").get_json()
    assert h["status"] == "degraded" and h["model_loaded"] is False
    assert h["detector"]["state"] == "disabled" and h["detector"]["final_model"] is False


def test_flows_are_stored_but_not_scored(app, proc, monkeypatch):
    monkeypatch.setattr(proc, "model_loaded", True)
    with app.app_context():
        r = store_flow(proc, flow("10.0.0.5", "8.8.8.8", 5000, 443, 1000.0, 1001.0, 500, 900))
        assert r["detection_status"] == "unsupported" and r["anomaly_score"] is None and r["alert"] is None
        assert r["bytes_out"] == 500 and r["bytes_in"] == 900


def test_mocked_detector_interface_alert_carries_source(app, proc, monkeypatch):
    """MOCKED: a stub detector exercises the alert path; not a statement about detection quality."""
    import numpy as np

    class StubDetector:
        baseline_mean, baseline_std, baseline_max = 0.1, 0.05, 0.3
        def score(self, vec):
            return 50.0, np.ones(len(vec), dtype=np.float32)

    monkeypatch.setattr(proc, "kitnet", StubDetector())
    monkeypatch.setattr(proc, "model_loaded", True)
    monkeypatch.setattr(proc, "detector_backend", "kitnet_baseline")
    with app.app_context():
        r = proc.submit({"src_ip": "192.168.1.105", "dst_ip": "198.51.100.77", "dst_port": 443, "bytes": 1460},
                        event_type="network_packet", source="pcap")
        assert r["detection_status"] == "scored" and r["alert"] is not None
        alert = db.session.get(Alert, r["alert"]["id"])
        assert alert.source == "pcap" and alert.to_dict()["data_source"] == "pcap"


def test_database_failure_is_not_counted_as_ingested(app, proc, monkeypatch):
    with app.app_context():
        before = proc.counters()
        def boom():
            raise RuntimeError("disk full")
        monkeypatch.setattr(db.session, "commit", boom)
        r = proc.ingest({"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1"})
        monkeypatch.undo()
        db.session.rollback()
        after = proc.counters()
        assert r["error"].startswith("Event could not be stored") and "disk full" not in r["error"]
        assert after["events_ingested"] == before["events_ingested"]
        assert after["persist_failures"] == before["persist_failures"] + 1


def test_downstream_failure_keeps_the_event(app, proc, monkeypatch):
    import services.correlation as corr
    def broken(_):
        raise RuntimeError("correlation bug")
    monkeypatch.setattr(corr, "evaluate_network_flow", broken)
    with app.app_context():
        r = store_flow(proc, flow("10.0.0.5", "8.8.8.8", 5001, 443, 1000.0, 1001.0, 1, 1))
        assert r["processing_status"] == "downstream_error" and "Correlation failed" in r["processing_error"]
        assert Event.query.filter_by(event_uuid=r["event_uuid"]).count() == 1


# ======================================================================= correlation
def _app_event(proc, activity_id, user_id, action, ip, t, size):
    from datetime import datetime, timezone
    return proc.record_application_activity(
        activity_id=activity_id, user_id=user_id, action=action, outcome="success",
        occurred_at=datetime.fromtimestamp(t, tz=timezone.utc), client_ip=ip, context={"size_bytes": size},
    )


def test_portal_connection_correlation_high_confidence(app, proc):
    with app.app_context():
        t = 1_800_000_000.0
        store_flow(proc, flow("10.0.0.5", "10.0.0.1", 52000, 5000, t - 1, t + 3, 60_000, 2_000))
        store_flow(proc, flow("10.0.0.5", "10.0.0.1", 52001, 5000, t - 1, t + 3, 300, 200))  # too small
        a = _app_event(proc, 1, 1, "upload", "10.0.0.5", t, 50_000)
        links = EventCorrelation.query.all()
        assert len(links) == 1 and links[0].method == "app_server_connection" and links[0].confidence == "high"
        detail = Event.query.filter_by(event_uuid=a["event_uuid"]).one().details["correlation"]
        assert detail["status"] == "correlated" and detail["app_server_candidates"] == 1


def test_ambiguous_portal_connections_are_not_correlated(app, proc):
    with app.app_context():
        t = 1_800_000_100.0
        a = _app_event(proc, 2, 1, "upload", "10.0.0.5", t, 1_000)
        store_flow(proc, flow("10.0.0.5", "10.0.0.1", 52010, 5000, t - 1, t + 3, 5_000, 100))
        assert EventCorrelation.query.count() == 1  # one candidate so far
        store_flow(proc, flow("10.0.0.5", "10.0.0.1", 52011, 5000, t - 2, t + 4, 9_000, 100))
        assert EventCorrelation.query.count() == 0  # second candidate → the earlier link is withdrawn
        assert Event.query.filter_by(event_uuid=a["event_uuid"]).one().details["correlation"]["status"] == "ambiguous"


def test_shared_address_is_never_attributed(app, proc):
    with app.app_context():
        t = 1_800_000_200.0
        _app_event(proc, 3, 1, "download", "10.0.0.50", t - 30, 100)
        a = _app_event(proc, 4, 2, "download", "10.0.0.50", t, 100)   # second user, same address (NAT)
        f = store_flow(proc, flow("10.0.0.50", "203.0.113.9", 53000, 443, t + 5, t + 9, 5_000, 100))
        assert EventCorrelation.query.count() == 0
        assert Event.query.filter_by(event_uuid=a["event_uuid"]).one().details["correlation"]["status"] == "shared_address"
        assert f["user_id"] is None  # the flow stays unattributed


def test_download_then_external_upload_low_confidence(app, proc):
    with app.app_context():
        t = 1_800_000_300.0
        a = _app_event(proc, 5, 1, "download", "10.0.0.7", t, 40_000)
        store_flow(proc, flow("10.0.0.7", "203.0.113.20", 54000, 443, t + 20, t + 25, 45_000, 3_000))   # match
        store_flow(proc, flow("10.0.0.7", "203.0.113.21", 54001, 443, t + 21, t + 22, 1_000, 900))      # too small
        store_flow(proc, flow("10.0.0.7", "10.0.0.99", 54002, 445, t + 22, t + 23, 90_000, 100))        # internal
        store_flow(proc, flow("10.0.0.7", "203.0.113.22", 54003, 443, t + 999, t + 1000, 90_000, 100))  # outside window
        links = EventCorrelation.query.all()
        assert len(links) == 1
        link = links[0]
        assert link.method == "address_time_proximity" and link.confidence == "low"
        assert link.network_event.dst_ip == "203.0.113.20" and 19 < link.time_delta_s < 21
        assert "does not show whether the file was carried" in link.rationale
    analyst = login(app, "analyst01")
    detail = analyst.get(f"/api/v1/events/{a['event_uuid']}").get_json()
    assert detail["correlations"][0]["related_event"]["dst_ip"] == "203.0.113.20"


# ======================================================================= collector
class FakeSniffer:
    """Stands in for scapy.AsyncSniffer; `started_callback` mimics the capture socket opening."""
    instances = []

    def __init__(self, open_socket=True, **kwargs):
        self.kwargs = kwargs
        self.open_socket = open_socket
        self.running = False
        self.exception = None
        self.thread = None
        FakeSniffer.instances.append(self)

    def start(self):
        self.running = True
        self._stop = threading.Event()
        def run():
            if self.open_socket:
                self.kwargs["started_callback"]()
                self._stop.wait()
            else:
                self.exception = OSError("Network is down")
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self, join=True):
        self._stop.set()
        self.running = False


def _fake_live(monkeypatch, open_socket=True):
    monkeypatch.setattr(LiveCollector, "list_interfaces",
                        lambda self: [{"name": "eth-test", "description": "", "ips": [], "allowed": True},
                                      {"name": "eth-other", "description": "", "ips": [], "allowed": False}])
    monkeypatch.setattr(live_collector_mod, "capture_precheck", lambda: {"available": True, "reason": None})
    monkeypatch.setattr(live_collector_mod, "AsyncSniffer", lambda **kw: FakeSniffer(open_socket=open_socket, **kw))


def test_live_capture_persists_packets_and_flows(app, monkeypatch):
    _fake_live(monkeypatch)
    admin = login(app, "admin01")
    res = admin.post("/api/v1/collector/start", json={"mode": "live", "interface": "eth-test", "filter": "tcp"})
    assert res.status_code == 200 and res.get_json()["mode"] == "live"
    collector = LiveCollector.get_instance()
    for pkt in tls_session(client="10.0.0.5", server="93.184.216.34"):
        collector._on_packet(pkt)  # what the sniffer thread would deliver
    stopped = admin.post("/api/v1/collector/stop").get_json()
    assert stopped["status"] == "stopped" and stopped["packets_captured"] == 8
    with app.app_context():
        packets = Event.query.filter_by(event_type="network_packet").all()
        flows = Event.query.filter_by(event_type="network_flow").all()
        assert len(packets) == 8 and {p.source for p in packets} == {"live_capture"}
        assert len(flows) == 1 and flows[0].source == "live_capture"
        assert {p.flow_id for p in packets} == {flows[0].flow_id}  # packets linked, not re-processed
        assert flows[0].details["tls"]["sni"] == "files.example.com"
    status = admin.get("/api/v1/collector/status").get_json()
    assert status["events_ingested"] == 9 and status["flow_events_ingested"] == 1
    assert status["processing_errors"] == 0 and status["live_capture_verified"] is True


def test_live_start_validation_and_failures(app, monkeypatch):
    _fake_live(monkeypatch)
    admin = login(app, "admin01")
    assert admin.post("/api/v1/collector/start", json={"mode": "live"}).status_code == 400
    assert admin.post("/api/v1/collector/start", json={"mode": "live", "interface": "nope"}).status_code == 400
    r = admin.post("/api/v1/collector/start", json={"mode": "live", "interface": "eth-other"})
    assert r.status_code == 400 and "ALLOWED" in r.get_json()["error"]
    r = admin.post("/api/v1/collector/start", json={"mode": "live", "interface": "eth-test", "filter": "tcp; rm -rf /"})
    assert r.status_code == 400

    # The sniffer thread dies before the capture socket opens → FAILED, never "live"
    _fake_live(monkeypatch, open_socket=False)
    r = admin.post("/api/v1/collector/start", json={"mode": "live", "interface": "eth-test"})
    assert r.status_code == 503 and r.get_json()["mode"] == "failed"
    status = admin.get("/api/v1/collector/status").get_json()
    assert status["mode"] == "failed" and status["is_live"] is False and "Network is down" in status["last_collector_error"]
    assert admin.post("/api/v1/collector/stop").get_json()["mode"] == "stopped"


def test_capture_unavailable_on_host_is_reported(app, monkeypatch):
    monkeypatch.setattr(LiveCollector, "list_interfaces",
                        lambda self: [{"name": "eth-test", "description": "", "ips": [], "allowed": True}])
    monkeypatch.setattr(live_collector_mod, "capture_precheck",
                        lambda: {"available": False, "reason": "No packet-capture provider"})
    admin = login(app, "admin01")
    r = admin.post("/api/v1/collector/start", json={"mode": "live", "interface": "eth-test"})
    assert r.status_code == 503 and "No packet-capture provider" in r.get_json()["error"]
    h = admin.get("/api/v1/health").get_json()
    assert h["collector"]["mode"] == "failed" and h["components"]["live_capture"] == "unavailable"


def test_capture_precheck_detects_scapy_placeholder_socket(monkeypatch):
    class _NotAvailableSocket:  # Scapy's placeholder *class* when wpcap/libpcap is missing
        pass
    monkeypatch.setattr(live_collector_mod.conf, "L2listen", _NotAvailableSocket)
    pre = live_collector_mod.capture_precheck()
    assert pre["available"] is False and "Npcap" in pre["reason"]


def test_sniffer_dying_mid_capture_is_detected(app, monkeypatch):
    _fake_live(monkeypatch)
    admin = login(app, "admin01")
    assert admin.post("/api/v1/collector/start", json={"mode": "live", "interface": "eth-test"}).status_code == 200
    collector = LiveCollector.get_instance()
    collector._sniffer.exception = OSError("adapter removed")
    collector._sniffer.stop()
    collector._sniffer.thread.join(1)
    deadline = time.time() + 5
    while collector.mode != "failed" and time.time() < deadline:
        time.sleep(0.1)
    assert collector.mode == "failed" and "adapter removed" in collector.last_collector_error


def test_simulation_is_labelled_and_never_live(app):
    admin = login(app, "admin01")
    r = admin.post("/api/v1/collector/start", json={"mode": "simulation"})
    assert r.status_code == 200 and r.get_json()["mode"] == "simulation"
    assert admin.post("/api/v1/collector/start", json={"mode": "simulation"}).get_json()["status"] == "already_running"
    time.sleep(2.2)
    status = admin.get("/api/v1/collector/status").get_json()
    assert status["is_simulated"] is True and status["is_live"] is False and status["source"] == "simulation"
    admin.post("/api/v1/collector/stop")
    with app.app_context():
        sources = {e.source for e in Event.query.filter(Event.event_type.in_(("network_packet", "network_flow"))).all()}
        assert sources == {"simulation"}
    m = admin.get("/api/v1/metrics").get_json()
    assert m["data_source"] == "simulation"


def test_concurrent_start_requests_are_rejected(app):
    collector = LiveCollector.get_instance()
    collector._state_lock.acquire()
    try:
        assert collector.start_live_capture(simulate=True)["status"] == "busy"
    finally:
        collector._state_lock.release()


# ======================================================================= PCAP
def test_pcap_upload_creates_packet_and_flow_events(app, tmp_path):
    from scapy.utils import wrpcap
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), tls_session(client="10.0.0.8", server="93.184.216.34", cport=51111))
    admin = login(app, "admin01")
    with open(path, "rb") as fh:
        res = admin.post("/api/v1/collector/pcap", data={"file": (fh, "capture.pcap")}, content_type="multipart/form-data")
    assert res.status_code == 200, res.get_json()
    body = res.get_json()
    assert body["status"] == "completed" and body["total_packets"] == 8
    assert body["packet_events"] == 8 and body["flow_events"] == 1 and body["tls_handshakes"] == 2
    assert body["processing_errors"] == 0
    with app.app_context():
        f = Event.query.filter_by(event_type="network_flow", source="pcap").one()
        assert f.details["tls"]["sni"] == "files.example.com" and f.details["end_reason"] == "tcp_close"
    # Uploaded captures are deleted after analysis
    assert not list((tmp_path / "pcap_work").glob("*"))


def test_pcap_rejects_invalid_files(app):
    admin = login(app, "admin01")
    bad = admin.post("/api/v1/collector/pcap", data={"file": (io.BytesIO(b"not a capture"), "x.pcap")},
                     content_type="multipart/form-data")
    assert bad.status_code == 400 and "pcap" in bad.get_json()["error"].lower()


def test_pcap_stop_endpoint_and_cancellation(app):
    admin = login(app, "admin01")
    r = admin.post("/api/v1/collector/pcap/stop")
    assert r.status_code == 200 and r.get_json()["status"] == "not_running"

    collector = LiveCollector.get_instance()
    collector.is_pcap_processing = True
    try:
        r2 = admin.post("/api/v1/collector/pcap/stop")
        assert r2.status_code == 200 and r2.get_json()["status"] == "stopping"
        assert collector._pcap_stop_event.is_set()
    finally:
        collector.is_pcap_processing = False
        collector._pcap_stop_event.clear()


# ======================================================================= access control
def test_collector_and_operations_require_admin(app):
    anon, emp, analyst, admin = app.test_client(), login(app, "eng01"), login(app, "analyst01"), login(app, "admin01")
    for path in ("/api/v1/collector/start", "/api/v1/collector/stop", "/api/v1/collector/pcap",
                 "/api/v1/stream/start", "/api/v1/model/train"):
        assert anon.post(path, json={}).status_code == 401
        assert emp.post(path, json={}).status_code == 403
        assert analyst.post(path, json={}).status_code == 403, path
    assert analyst.get("/api/v1/collector/status").status_code == 200
    assert emp.get("/api/v1/collector/status").status_code == 403
    assert emp.get("/api/v1/events").status_code == 403
    assert analyst.get("/api/v1/events").status_code == 200
    stats = analyst.get("/api/v1/events/stats")  # static route wins over /events/<uuid>
    assert stats.status_code == 200 and "by_type" in stats.get_json()
    assert admin.post("/api/v1/collector/stop").status_code == 200
    # Analysts still triage alerts
    assert analyst.get("/api/v1/alerts").status_code == 200


def test_ingestion_cannot_impersonate_or_fake_sources(app):
    c = app.test_client()
    r = c.post("/api/v1/events", json={"event_type": "application_activity", "src_ip": "10.0.0.1"})
    assert r.status_code == 400
    r = c.post("/api/v1/events", json={"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "user_id": 1,
                                       "source": "live_capture", "device_id": "ceo-laptop"})
    body = r.get_json()
    assert body["user_id"] is None and body["source"] == "api" and body["device_id"] == "10.0.0.1"
    assert c.post("/api/v1/events", json={"src_ip": "not-an-ip"}).status_code == 400
    # Idempotent re-submission with an event_id
    a = c.post("/api/v1/events", json={"event_id": "sensor-1-42", "src_ip": "10.0.0.2"}).get_json()
    b = c.post("/api/v1/events", json={"event_id": "sensor-1-42", "src_ip": "10.0.0.2"}).get_json()
    assert b["duplicate"] is True and a["event_uuid"] == b["event_uuid"]


def test_ingest_api_key(app):
    app.config["INGEST_API_KEY"] = "k3y"
    c = app.test_client()
    assert c.post("/api/v1/events", json={"src_ip": "10.0.0.1"}).status_code == 401
    assert c.post("/api/v1/events", json={"src_ip": "10.0.0.1"}, headers={"X-Ingest-Key": "wrong"}).status_code == 401
    assert c.post("/api/v1/events", json={"src_ip": "10.0.0.1"}, headers={"X-Ingest-Key": "k3y"}).status_code in (201, 202)
    assert login(app, "admin01").get("/api/v1/health").get_json()["ingestion_auth"] == "api_key"


# ======================================================================= health
def test_health_hides_details_from_anonymous_and_is_honest(app):
    anon = app.test_client().get("/api/v1/health").get_json()
    assert "collector" not in anon and "counters" not in anon and anon["database"] == "connected"
    h = login(app, "analyst01").get("/api/v1/health").get_json()
    assert h["detector"]["final_model"] is False
    assert h["collector"]["mode"] == "stopped" and h["collector"]["is_live"] is False
    assert h["tls"]["ja4"] == "unsupported" and h["tls"]["zeek"]["available"] in (True, False)
    assert h["sse"]["max_subscribers"] == app.config["SSE_MAX_SUBSCRIBERS"]


# ======================================================================= SSE
def test_sse_requires_soc_role(app):
    assert app.test_client().get("/api/v1/stream/live").status_code == 401
    assert login(app, "eng01").get("/api/v1/stream/live").status_code == 403


def test_sse_delivers_typed_messages_and_cleans_up(app, proc):
    analyst = login(app, "analyst01")
    before = proc.subscriber_count
    resp = analyst.get("/api/v1/stream/live", buffered=False)
    assert resp.status_code == 200 and resp.mimetype == "text/event-stream"
    chunks = iter(resp.response)
    assert next(chunks).startswith(b"retry:")
    hello = next(chunks).decode()
    assert '"type": "hello"' in hello and '"detector"' in hello
    assert proc.subscriber_count == before + 1
    proc.broadcast("alert", {"id": 1})
    msg = next(chunks).decode()
    assert msg.startswith("id: ") and '"type": "alert"' in msg
    resp.close()  # client disconnect
    assert proc.subscriber_count == before


def test_sse_subscriber_cap(app, proc):
    app.config["SSE_MAX_SUBSCRIBERS"] = proc.subscriber_count
    assert login(app, "analyst01").get("/api/v1/stream/live").status_code == 503


# ======================================================================= migration
OLD_EVENTS_DDL = """
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_uuid VARCHAR(64) NOT NULL UNIQUE, received_at DATETIME,
  event_time DATETIME, src_ip VARCHAR(45) NOT NULL, dst_ip VARCHAR(45) NOT NULL, src_port INTEGER,
  dst_port INTEGER, protocol VARCHAR(10), bytes_transferred BIGINT, packet_count INTEGER,
  flow_duration FLOAT, raw_event_json TEXT, ai_processed BOOLEAN, ai_error TEXT, anomaly_score FLOAT,
  feature_vector_json TEXT, alert_id INTEGER REFERENCES alerts(id))
"""


def test_migration_upgrades_old_schema_without_losing_rows(tmp_path):
    main, auth = tmp_path / "main.db", tmp_path / "users.db"
    con = sqlite3.connect(main)
    con.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, alert_uuid VARCHAR(64), created_at DATETIME, severity VARCHAR(16), risk_score FLOAT, anomaly_score FLOAT, z_score FLOAT, confidence FLOAT, src_ip VARCHAR(45), dst_ip VARCHAR(45), src_port INTEGER, dst_port INTEGER, protocol VARCHAR(10), bytes_transferred BIGINT, off_hours BOOLEAN, is_external_dst BOOLEAN, evidence_json TEXT, explanation TEXT, mitigation_json TEXT, risk_factors_json TEXT, status VARCHAR(24), disposition VARCHAR(32), analyst_notes TEXT, updated_at DATETIME, resolved_at DATETIME, model_version_id INTEGER)")
    con.execute(OLD_EVENTS_DDL)
    con.execute("INSERT INTO events (event_uuid, src_ip, dst_ip, ai_processed, anomaly_score) VALUES ('EVT-OLD1', '10.0.0.1', '1.1.1.1', 1, 0.5)")
    con.execute("INSERT INTO events (event_uuid, src_ip, dst_ip, ai_processed, ai_error) VALUES ('EVT-OLD2', '10.0.0.2', '1.1.1.1', 0, 'Model not loaded — event was not evaluated.')")
    con.commit()
    con.close()

    class OldDbConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{main}"
    app = create_app(OldDbConfig)
    app.config["SQLALCHEMY_BINDS"] = {"auth": f"sqlite:///{auth}"}
    with app.app_context():
        rows = {e.event_uuid: e for e in Event.query.all()}
        assert set(rows) == {"EVT-OLD1", "EVT-OLD2"}
        assert rows["EVT-OLD1"].event_type == "network_record" and rows["EVT-OLD1"].source == "legacy"
        assert rows["EVT-OLD1"].detection_status == "scored" and rows["EVT-OLD2"].detection_status == "unavailable"
        # New-style rows (application events without a destination) now fit
        EventProcessor.get_instance().record_application_activity(
            activity_id=1, user_id=1, action="upload", outcome="success", occurred_at=None, client_ip=None, context={})
        assert Event.query.filter_by(event_type="application_activity").count() == 1
        db.session.remove()
        for engine in db.engines.values():
            engine.dispose()
    assert list((tmp_path / "backups").glob("main.*.db")), "a backup is taken before the table rebuild"
