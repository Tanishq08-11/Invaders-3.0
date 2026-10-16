"""
End-to-end proof of the final detection pipeline (no stubbed model, no stubbed detectors):

  packets → FlowAggregator → EventProcessor.submit(network_flow)
          → canonical 78-feature vector → TrustLab KitNET bundle (anomaly score vs 0.07018400015809657)
          → DetectionEngine.run() (D1–D28) → detection_summary_json
          → hybrid_risk (AI + rules) → one persisted alert → Flask API JSON (React contract)

The model and the engine are wrapped with call recorders (they still run for real) so the
test can prove they executed. The API responses are written to
frontend/src/test/fixtures/hybrid_pipeline.json, which the frontend test parses with the
dashboard's zod schemas.
"""
import hashlib
import json
import os
import subprocess

import numpy as np
import pytest

from app import create_app
from config import Config
from core.database import db
from core.models import Alert, DetectionSignal, Event
from ml.risk_engine import hybrid_risk
from ml.trustlab_adapter import TrustLabKitNET
from services.detection import scheduler
from services.detection.engine import DetectionEngine
from services.event_processor import EventProcessor
from services.flow_aggregator import FlowAggregator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(ROOT, "ml", "kitnet_trustlab_bundle.pkl")
FIXTURE = os.path.join(ROOT, "frontend", "src", "test", "fixtures", "hybrid_pipeline.json")
THRESHOLD = 0.07018400015809657
T0 = 1760421600.0   # Tue 2025-10-14 06:00 UTC


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    INGEST_API_KEY = ""


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def proc():
    p = EventProcessor.get_instance()
    if not isinstance(p.kitnet, TrustLabKitNET) or not p.model_loaded:
        p.reload_model()
    return p


@pytest.fixture
def recorders(proc, monkeypatch):
    """Record (not replace) every model and rule-engine call."""
    calls = {"score": [], "run": []}
    real_score = proc.kitnet.score
    engine = DetectionEngine.get_instance()
    real_run = engine.run

    def score(x):
        out = real_score(x)
        calls["score"].append((np.asarray(x).copy(), out[0]))
        return out

    def run(ev, *a, **kw):
        out = real_run(ev, *a, **kw)
        calls["run"].append((ev.event_uuid, kw, out))
        return out

    monkeypatch.setattr(proc.kitnet, "score", score)
    monkeypatch.setattr(engine, "run", run)
    return calls


def _pkt(ts, src, sport, dst, dport, flags, size, window=64240):
    return {"timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": "TCP", "bytes": size, "payload_bytes": max(0, size - 54), "tcp_flags": flags,
            "header_bytes": 40, "tcp_window": window}


def tcp_flow(client, cport, server, sport, data_packets, size=1514, gap=0.002, t0=T0):
    """A complete TCP connection (handshake, data, FIN/FIN) through the real aggregator."""
    agg = FlowAggregator()
    pkts = [_pkt(t0, client, cport, server, sport, "S", 74),
            _pkt(t0 + 0.01, server, sport, client, cport, "SA", 74, 65160),
            _pkt(t0 + 0.02, client, cport, server, sport, "A", 66)]
    t = t0 + 0.03
    for i in range(data_packets):
        pkts.append(_pkt(t, client, cport, server, sport, "PA", size))
        t += gap
        if i % 20 == 19:
            pkts.append(_pkt(t, server, sport, client, cport, "A", 66, 65160))
            t += gap
    pkts += [_pkt(t, client, cport, server, sport, "FA", 66), _pkt(t + 0.01, server, sport, client, cport, "FA", 66, 65160)]
    done = []
    for p in pkts:
        done += agg.update(p)[1]
    assert len(done) == 1 and done[0]["details"]["end_reason"] == "tcp_close"
    return done[0]


def submit(proc, flow):
    return proc.submit(flow, event_type="network_flow", source="pcap", dedup_key=f"flow:{flow['flow_id']}")


def _sha(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# --------------------------------------------------------------------------- model identity
def test_authoritative_bundle_is_loaded_unmodified(proc):
    assert proc.model_loaded and isinstance(proc.kitnet, TrustLabKitNET)
    assert len(proc.feature_names) == 78 and proc.feature_names[-4:] == ["HourSin", "HourCos", "DaySin", "DayCos"]
    assert proc.threshold == THRESHOLD
    assert proc.bundle_sha256 == _sha(BUNDLE)
    st = proc.detector_status()
    assert st["state"] == "ready" and st["final_model"] is True and st["input_dimension"] == 78
    # The pickle in the working tree is byte-identical to the committed one.
    r = subprocess.run(["git", "diff", "--quiet", "--", "ml/kitnet_trustlab_bundle.pkl"], cwd=ROOT)
    assert r.returncode == 0


def test_retired_backend_is_not_a_fallback(proc, monkeypatch):
    monkeypatch.setattr(proc, "detector_backend", "kitnet_baseline")
    assert proc.detector_status()["state"] == "unavailable"


# --------------------------------------------------------------------------- full pipeline
def _assert_pipeline(proc, calls, r):
    ev = db.session.get(Event, r["id"])
    # 2-3. the authoritative 78-feature model ran on this flow and produced a score
    assert ev.detection_status == "scored" and ev.ai_processed is True
    x, score = calls["score"][-1]
    assert x.shape == (78,)
    assert ev.anomaly_score == pytest.approx(score)
    fv = json.loads(ev.feature_vector_json)
    assert fv["names"] == proc.feature_names and len(fv["values"]) == 78
    assert np.allclose(fv["values"], x)
    # Independent check: a fresh load of the bundle gives the same score for the same vector.
    fresh = TrustLabKitNET()
    fresh.load_bundle(BUNDLE)
    assert fresh.score(np.array(fv["values"]))[0] == pytest.approx(ev.anomaly_score, rel=1e-9)
    # Rule outputs are not model inputs.
    assert not any(n.startswith("D") and n[1:].isdigit() for n in fv["names"])
    measured = [n for n, s in fv["sources"].items() if s == "observed"]
    assert {"Flow Duration", "Fwd Pkt Len Mean", "Init Fwd Win Byts", "Fwd Header Len", "HourSin"} <= set(measured)

    # 4-6. DetectionEngine.run executed on this event and the summary is populated
    uuid_, kw, out = calls["run"][-1]
    assert uuid_ == ev.event_uuid and kw["create_alert"] is False
    summary = json.loads(ev.detection_summary_json)
    assert summary["engine_version"] and summary["entity_key"]
    for det in ("D1", "D2", "D5", "D6", "D8", "D20", "D21", "D23", "D28"):
        assert det in summary["results"]
    assert set(summary) >= {"triggered", "not_evaluated", "errors", "rule_score", "rule_severity"}
    for k in summary["not_evaluated"]:
        assert summary["results"][k]["reason"]          # insufficient-data states carry their reason

    # 7. hybrid correlation
    h = json.loads(ev.hybrid_risk_json)
    assert h["anomaly_score"] == pytest.approx(ev.anomaly_score)
    assert h["anomaly_threshold"] == THRESHOLD and h["model_status"] == "scored"
    assert h["is_anomalous"] == (ev.anomaly_score > THRESHOLD)
    assert h["final_risk_score"] is not None and h["final_risk_level"] and h["explanation"]
    assert h["feature_coverage"]["total"] == 78
    return ev, summary, h


def test_flow_without_rule_trigger(app, proc, recorders):
    flow = tcp_flow("10.20.0.15", 51515, "93.184.216.34", 443, data_packets=40)
    r = submit(proc, flow)
    ev, summary, h = _assert_pipeline(proc, recorders, r)
    assert summary["triggered"] == [] and h["triggered_detectors"] == [] and h["rule_score"] is None
    if h["is_anomalous"]:
        # AI-only alert: KitNET flagged it, no rule corroborated
        assert h["alert"] and h["detection_source"] == "ai"
        alert = db.session.get(Alert, ev.alert_id)
        assert alert.detection_source == "ai" and alert.anomaly_score == pytest.approx(ev.anomaly_score)
        assert alert.rule_score is None and json.loads(alert.evidence_json)
    else:
        assert not h["alert"] and h["detection_source"] == "none" and ev.alert_id is None
        assert Alert.query.count() == 0
    print(f"\n[no-rule flow] anomaly_score={ev.anomaly_score:.6f} threshold={THRESHOLD} "
          f"anomalous={h['is_anomalous']} source={h['detection_source']} coverage={h['feature_coverage']}")


def test_flow_with_rule_trigger_creates_one_correlated_alert(app, proc, recorders):
    # Outbound TCP/3389 to an external address, ~11 MB: D20 (remote desktop out) → HIGH.
    flow = tcp_flow("10.20.0.16", 52000, "198.51.100.23", 3389, data_packets=7300)
    r = submit(proc, flow)
    ev, summary, h = _assert_pipeline(proc, recorders, r)
    assert "D20" in summary["triggered"]
    d20 = summary["results"]["D20"]
    assert d20["status"] == "triggered" and d20["severity"] == "HIGH" and d20["reason"]
    trig = {t["detector_id"]: t for t in h["triggered_detectors"]}
    assert trig["D20"]["severity"] == "HIGH" and trig["D20"]["observed"]["service_port"] == 3389
    assert h["rule_score"] is not None and h["rule_alert_due"] is True and h["alert"] is True
    assert h["detection_source"] == ("hybrid" if h["is_anomalous"] else "rules")

    # 8. exactly one alert, persisted with both components
    assert Alert.query.count() == 1
    alert = db.session.get(Alert, ev.alert_id)
    assert alert.detection_source == h["detection_source"]
    assert alert.anomaly_score == pytest.approx(ev.anomaly_score)       # model evidence kept even if normal
    assert alert.rule_score == h["rule_score"] and alert.risk_score == h["final_risk_score"]
    assert alert.severity in ("HIGH", "CRITICAL")
    assert [s["detector_id"] for s in alert.rule_signals] == [k for k in summary["triggered"]
                                                             if trig[k]["category"] == "security"]
    sig = DetectionSignal.query.filter_by(detector_id="D20", event_id=ev.id).one()
    assert sig.alert_id == alert.id
    assert summary["alert_created"] is True and summary["alert_id"] == alert.alert_uuid

    # 9. what React receives
    c = app.test_client()
    a = c.get(f"/api/v1/alerts/{alert.id}").get_json()
    assert a["detection_source"] == h["detection_source"] and a["anomaly_threshold"] == THRESHOLD
    assert a["model_status"] == "scored" and a["hybrid_risk"]["final_risk_score"] == h["final_risk_score"]
    assert any(s["code"] == "D20" for s in a["signals"])
    e = c.get(f"/api/v1/events/{ev.event_uuid}").get_json()
    assert e["detection_summary"]["triggered"] == summary["triggered"]
    assert e["hybrid_risk"]["detection_source"] == h["detection_source"]
    lst = c.get("/api/v1/alerts").get_json()
    items = lst["items"] if isinstance(lst, dict) else lst
    assert items[0]["detection_source"] == h["detection_source"]
    os.makedirs(os.path.dirname(FIXTURE), exist_ok=True)
    with open(FIXTURE, "w", encoding="utf-8") as fh:
        json.dump({"alert_detail": a, "alert_list": lst, "event_detail": e}, fh, indent=1, default=str)
    print(f"\n[rule flow] anomaly_score={ev.anomaly_score:.6f} rule_score={h['rule_score']} "
          f"final={h['final_risk_score']} {h['final_risk_level']} source={h['detection_source']}")


def test_resubmitted_flow_is_not_evaluated_twice(app, proc, recorders):
    flow = tcp_flow("10.20.0.17", 52001, "198.51.100.24", 3389, data_packets=7300)
    submit(proc, flow)
    again = submit(proc, flow)
    assert again["duplicate"] is True and Alert.query.count() == 1 and len(recorders["run"]) == 1


def test_packets_are_not_scored_individually(app, proc, recorders):
    r = proc.submit(_pkt(T0, "10.20.0.18", 50000, "93.184.216.34", 443, "S", 74), event_type="network_packet",
                    source="pcap")
    assert r["detection_status"] == "unsupported" and r["hybrid_risk"] is None
    assert recorders["score"] == [] and recorders["run"] == []


# --------------------------------------------------------------------------- hybrid policy
MODEL_ANOM = {"status": "scored", "anomaly_score": 0.21, "threshold": THRESHOLD, "is_anomalous": True,
              "top_features": [{"feature_name": "Flow IAT Max"}], "feature_coverage": {"total": 78, "imputed": 14}}
MODEL_NORMAL = {**MODEL_ANOM, "anomaly_score": 0.03, "is_anomalous": False}
NO_RULES = {"status": "evaluated", "summary": {"results": {"D4": {"status": "not_evaluated", "reason": "short"}},
                                               "not_evaluated": ["D4"], "errors": []},
            "triggered": [], "rule_score": None, "alert_due": False}
RULE_HIT = {"status": "evaluated", "summary": {"results": {}, "not_evaluated": [], "errors": ["D9"]},
            "triggered": [{"detector_id": "D20", "name": "Remote desktop out", "category": "security",
                           "severity": "HIGH", "score": 70.0, "reason": "3389 out", "evidence": []}],
            "rule_score": 56.0, "rule_severity": "MEDIUM", "alert_due": True}


def test_hybrid_ai_only():
    h = hybrid_risk(MODEL_ANOM, NO_RULES)
    assert h["alert"] and h["detection_source"] == "ai" and h["rule_score"] is None
    assert h["final_risk_score"] == h["ai_risk_score"] and h["insufficient_data"][0]["detector_id"] == "D4"


def test_hybrid_rules_only_keeps_rule_evidence_and_model_score():
    h = hybrid_risk(MODEL_NORMAL, RULE_HIT)
    assert h["alert"] and h["detection_source"] == "rules" and h["anomaly_score"] == 0.03
    assert h["triggered_detectors"][0]["detector_id"] == "D20" and h["detector_errors"][0]["detector_id"] == "D9"


def test_hybrid_both():
    h = hybrid_risk(MODEL_ANOM, RULE_HIT)
    assert h["detection_source"] == "hybrid"
    assert h["final_risk_score"] > max(h["ai_risk_score"], h["rule_score"])


def test_hybrid_nothing_and_model_unavailable():
    assert hybrid_risk(MODEL_NORMAL, NO_RULES)["alert"] is False
    h = hybrid_risk({"status": "unavailable", "reason": "bundle missing"}, RULE_HIT)
    assert h["anomaly_score"] is None and h["ai_risk_score"] is None and h["final_risk_score"] == 56.0


# --------------------------------------------------------------------------- sweep scheduler
def test_sweep_runs_without_duplicate_signals(app):
    scheduler.run_once(app)
    n = DetectionSignal.query.count()
    scheduler.run_once(app)
    assert DetectionSignal.query.count() == n and scheduler.last_run["error"] is None
    assert Alert.query.count() == 0                 # sweeps never create alerts


def test_scheduler_guards(app, monkeypatch):
    assert scheduler.start(app) is False            # TESTING
    app.config.update(TESTING=False, DEBUG=True)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)
    try:
        assert scheduler.start(app) is False        # reloader watcher process
        app.config["DETECTION_SWEEP_ENABLED"] = False
        monkeypatch.setenv("WERKZEUG_RUN_MAIN", "true")
        assert scheduler.start(app) is False        # disabled by config
    finally:
        app.config.update(TESTING=True, DEBUG=False, DETECTION_SWEEP_ENABLED=True)
