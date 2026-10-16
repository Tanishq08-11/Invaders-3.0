"""
TrustLab model contract — the 15 mandatory integration tests, plus inference-only and timestamp
consistency checks, and the two end-to-end scenarios (normal flow → no alert; exfiltration flow →
anomaly → DetectionEngine → hybrid risk → persisted alert → API).

Time note: the bundle's training data covers essentially one weekday (DaySin/DayCos at day 6,
Monday=0) around midday, so "normal" scenarios use Sunday 12:00 UTC. At other times the time
features alone put flows above the threshold — a property of the trained model, not of this code.
"""
import copy
import json
import math

import numpy as np
import pytest

import services.event_processor as ep_module
from app import create_app
from config import Config
from core.database import db
from core.models import Alert, Event
from ml.trustlab_adapter import EXPECTED_FEATURE_ORDER, TrustLabKitNET
from ml.trustlab_features import IMPUTED, NOT_MEASURED, build_feature_vector, build_from_cic_record, time_features
from services.detection.engine import DetectionEngine
from services.event_processor import EventProcessor
from test_hybrid_pipeline import BUNDLE, THRESHOLD, tcp_flow

SUNDAY_NOON = 1760875200.0   # 2025-10-19 12:00:00 UTC, weekday 6 (Monday=0)


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


@pytest.fixture(scope="module")
def model():
    m = TrustLabKitNET()
    m.load_bundle(BUNDLE)
    return m


@pytest.fixture
def proc():
    p = EventProcessor.get_instance()
    if not isinstance(p.kitnet, TrustLabKitNET) or not p.model_loaded:
        p.reload_model()
    return p


def flow_vector(m, flow, ts):
    return build_feature_vector(event_type="network_flow",
                                columns={"src_port": flow["src_port"], "dst_port": flow["dst_port"], "protocol": "TCP",
                                         "duration": flow["duration"], "timestamp": ts},
                                details=flow["details"], raw_record=None, feature_names=m.feature_names,
                                medians=m.medians, tz_name="UTC", port_orientation=Config.TRUSTLAB_PORT_ORIENTATION)


def benign_flow():
    return tcp_flow("10.30.0.5", 50100, "93.184.216.34", 443, data_packets=3, size=120, gap=0.0005, t0=SUNDAY_NOON)


def exfil_flow():
    return tcp_flow("10.30.0.6", 50200, "198.51.100.23", 443, data_packets=7300, t0=SUNDAY_NOON)


# 1, 2 ----------------------------------------------------------------------------------
def test_01_feature_count(model):
    fv = flow_vector(model, benign_flow(), SUNDAY_NOON)
    assert fv.values.shape == (78,) and len(model.feature_names) == 78


def test_02_exact_feature_order(model):
    assert model.feature_names == EXPECTED_FEATURE_ORDER
    assert flow_vector(model, benign_flow(), SUNDAY_NOON).names == EXPECTED_FEATURE_ORDER


# 3 -------------------------------------------------------------------------------------
def test_03_timestamp_features(model):
    fv = flow_vector(model, benign_flow(), SUNDAY_NOON)
    v = dict(zip(fv.names, fv.values))
    hour, day = 12.0, 6
    assert v["HourSin"] == pytest.approx(math.sin(2 * math.pi * hour / 24), abs=1e-6)
    assert v["HourCos"] == pytest.approx(math.cos(2 * math.pi * hour / 24), abs=1e-6)
    assert v["DaySin"] == pytest.approx(math.sin(2 * math.pi * day / 7), abs=1e-9)
    assert v["DayCos"] == pytest.approx(math.cos(2 * math.pi * day / 7), abs=1e-9)
    assert all(fv.sources[n] == "observed" for n in ("HourSin", "HourCos", "DaySin", "DayCos"))


def test_03b_one_timestamp_interpretation():
    # epoch, epoch-ms, ISO and CICFlowMeter strings → identical time features
    variants = [SUNDAY_NOON, SUNDAY_NOON * 1000, "2025-10-19T12:00:00Z", "19/10/2025 12:00:00"]
    from ml.trustlab_features import parse_timestamp
    feats = [time_features(parse_timestamp(v, "UTC"), "UTC") for v in variants]
    assert all(f == pytest.approx(feats[0]) for f in feats)


# 4 -------------------------------------------------------------------------------------
def test_04_medians_for_unavailable(model):
    fv = flow_vector(model, benign_flow(), SUNDAY_NOON)
    for name in NOT_MEASURED:
        assert fv.sources[name] == IMPUTED
        assert fv.values[fv.names.index(name)] == model.medians[name]
    empty = build_from_cic_record({}, model.feature_names, model.medians, "UTC")
    assert all(empty.sources[n] == IMPUTED for n in model.feature_names)
    assert np.allclose(empty.values, [model.medians[n] for n in model.feature_names])


# 5, 6 ----------------------------------------------------------------------------------
def test_05_bundle_loads(model):
    assert len(model.ensemble) == 28 and model.output_ae is not None
    hp = model.hyperparameters
    assert (hp["m"], hp["lr"], hp["hr"], hp["n"]) == (10, 0.1, 0.75, 78)
    assert (hp["FM_grace_period"], hp["AD_grace_period"]) == (5000, 15000)
    assert (model.fm_grace_period, model.ad_grace_period) == (5000, 15000)


def test_06_threshold_from_bundle(model, proc):
    import pickle
    from ml.trustlab_adapter import _install_stubs
    _install_stubs()
    with open(BUNDLE, "rb") as fh:
        raw = pickle.load(fh)
    assert model.threshold == raw["threshold"] == THRESHOLD == proc.threshold


def test_06b_inference_does_not_modify_the_model(model):
    before = copy.deepcopy([(ae.W, ae.hbias, ae.vbias, ae.norm_min, ae.norm_max) for ae in model.ensemble])
    out_before = copy.deepcopy((model.output_ae.W, model.output_ae.norm_max))
    x = flow_vector(model, exfil_flow(), SUNDAY_NOON).values
    s1 = model.score(x)[0]
    for _ in range(5):
        model.score(x)
    assert model.score(x)[0] == s1
    after = [(ae.W, ae.hbias, ae.vbias, ae.norm_min, ae.norm_max) for ae in model.ensemble]
    for b, a in zip(before, after):
        assert all(np.array_equal(p, q) for p, q in zip(b, a))
    assert np.array_equal(out_before[0], model.output_ae.W) and np.array_equal(out_before[1], model.output_ae.norm_max)


# 7, 8 ----------------------------------------------------------------------------------
def test_07_benign_flow_finite_and_normal(model):
    out = model.score_features(flow_vector(model, benign_flow(), SUNDAY_NOON).values)
    assert np.isfinite(out["anomaly_score"])
    assert out["is_anomaly"] is False and out["anomaly_score"] < THRESHOLD


def test_08_exfiltration_flow_exceeds_threshold(model):
    out = model.score_features(flow_vector(model, exfil_flow(), SUNDAY_NOON).values)
    assert out["anomaly_score"] > THRESHOLD and out["is_anomaly"] is True


# 9-13: end-to-end ----------------------------------------------------------------------
def test_09_to_13_end_to_end(app, proc, monkeypatch):
    calls = []
    engine = DetectionEngine.get_instance()
    real_run = engine.run
    monkeypatch.setattr(engine, "run", lambda ev, *a, **kw: calls.append(ev.event_uuid) or real_run(ev, *a, **kw))

    # NORMAL FLOW → score → no/low risk, no alert
    nf = benign_flow()
    rn = proc.submit(nf, event_type="network_flow", source="pcap", dedup_key=f"flow:{nf['flow_id']}")
    evn = db.session.get(Event, rn["id"])
    hn = json.loads(evn.hybrid_risk_json)
    assert evn.anomaly_score < THRESHOLD and hn["is_anomalous"] is False
    assert hn["alert"] is False and evn.alert_id is None and hn["final_risk_level"] in ("NORMAL", "LOW")

    # ABNORMAL EXFILTRATION FLOW → anomaly → DetectionEngine → risk → alert
    xf = exfil_flow()
    rx = proc.submit(xf, event_type="network_flow", source="pcap", dedup_key=f"flow:{xf['flow_id']}")
    evx = db.session.get(Event, rx["id"])
    assert calls == [evn.event_uuid, evx.event_uuid]                     # 9: run() executed per flow
    summary = json.loads(evx.detection_summary_json)                     # 10: summary populated
    assert summary["results"]
    hx = json.loads(evx.hybrid_risk_json)
    assert evx.anomaly_score > THRESHOLD and hx["is_anomalous"] is True
    assert hx["alert"] is True and evx.alert_id is not None              # 11: anomalous flow → alert
    alert = db.session.get(Alert, evx.alert_id)
    assert alert.anomaly_score == pytest.approx(evx.anomaly_score)
    assert alert.detection_source in ("ai", "hybrid") and alert.severity in ("HIGH", "CRITICAL")
    a = app.test_client().get(f"/api/v1/alerts/{alert.id}").get_json()
    for key in ("created_at", "source_ip", "destination", "destination_port", "anomaly_score",
                "anomaly_threshold", "detection_source", "severity", "risk_score", "explanation"):
        assert a.get(key) is not None, key
    assert a["metadata"]["protocol"] == "TCP" and a["metadata"]["source_port"] == 50200
    assert a["hybrid_risk"]["insufficient_data"] is not None              # detector results travel with it

    # 12: every registered detector for this event type was executed
    expected = {d.id for d in engine.detectors if "network_flow" in d.event_types}
    assert expected <= set(summary["results"]) and len(expected) >= 20

    # 13: INSUFFICIENT_DATA never counts as positive evidence
    insufficient = [k for k, r in summary["results"].items() if r["outcome"] == "INSUFFICIENT_DATA"]
    assert insufficient                                                   # e.g. D2/D4/D7 without history
    trig = {t["detector_id"] for t in hx["triggered_detectors"]}
    signals = {s["detector_id"] for s in alert.rule_signals}
    for k in insufficient:
        r = summary["results"][k]
        assert r["triggered"] is False and "severity" not in r and "evidence" not in r and r["reason"]
        assert k not in trig and k not in signals and k not in summary["triggered"]


def test_13b_ai_alert_does_not_require_a_rule(app, proc):
    xf = exfil_flow()
    r = proc.submit(xf, event_type="network_flow", source="pcap", dedup_key=f"flow:{xf['flow_id']}")
    h = r["hybrid_risk"]
    if not h["triggered_detectors"]:
        assert h["alert"] and h["detection_source"] == "ai"


# 14 ------------------------------------------------------------------------------------
def test_14_predict_api_matches_live_pipeline(app, proc):
    record = {name: proc.medians[name] for name in proc.feature_names[3:74]}
    record.update({"Src Port": 50300, "Dst Port": 443, "Protocol": 6, "Timestamp": "19/10/2025 12:00:00",
                   "Flow Duration": 2500000, "TotLen Fwd Pkts": 9000000, "Tot Fwd Pkts": 6200,
                   "src_ip": "10.30.0.7", "dst_ip": "198.51.100.40"})
    c = app.test_client()
    pred = c.post("/api/v1/model/predict", json=record).get_json()
    live = c.post("/api/v1/events", json=record).get_json()
    assert live["detection_status"] == "scored"
    assert pred["model"] == "kitnet_trustlab" and pred["feature_count"] == 78 and pred["threshold"] == THRESHOLD
    assert live["anomaly_score"] == pytest.approx(pred["anomaly_score"], rel=1e-6)
    assert live["hybrid_risk"]["is_anomalous"] == pred["is_anomaly"]
    ev = Event.query.filter_by(event_uuid=live["event_uuid"]).one()
    assert json.loads(ev.feature_vector_json)["names"] == EXPECTED_FEATURE_ORDER
    batch = c.post("/api/v1/model/predict/batch", json={"flows": [record]}).get_json()
    assert batch["results"][0]["anomaly_score"] == pytest.approx(pred["anomaly_score"], rel=1e-9)


# 15 ------------------------------------------------------------------------------------
def test_15_no_legacy_model_in_production(app, proc):
    assert isinstance(proc.kitnet, TrustLabKitNET) and proc.kitnet.input_dim == 78
    for legacy in ("AfterImage", "KitNET", "ExplanationEngine"):
        assert not hasattr(ep_module, legacy)
    for dim in (74, 100):
        with pytest.raises((AssertionError, ValueError)):
            proc.kitnet.score_features(np.zeros(dim))
    h = app.test_client().get("/api/v1/model/health").get_json()
    assert h == {**h, "model": "kitnet_trustlab", "loaded": True, "feature_count": 78, "threshold": THRESHOLD,
                 "fm_grace_period": 5000, "ad_grace_period": 15000}
    assert "path" not in json.dumps(h).lower()


def test_15b_hot_swap_and_legacy_thresholds_cannot_change_the_decision(app, proc):
    c = app.test_client()
    r = c.post("/api/v1/model/thresholds", json={"z_low": 0.1}).get_json()
    assert r["trustlab_threshold"] == THRESHOLD and proc.threshold == THRESHOLD
    v = c.post("/api/v1/model/verify", json={"deploy": True})
    assert v.status_code == 409 and isinstance(proc.kitnet, TrustLabKitNET)
