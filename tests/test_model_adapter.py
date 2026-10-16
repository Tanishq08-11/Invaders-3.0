"""
Automated Tests for Model Management & Teammate Model Integration
==================================================================
Validates:
  • POST /api/v1/model/verify endpoint
  • ModelManager.verify_model calibration and latency benchmarking
  • TeammateModelAdapter wrapping custom models, callables, and estimators
  • Dynamic model hot-swapping into the active EventProcessor pipeline
"""
import pytest
import numpy as np
from app import create_app
from core.database import db
from config import Config
from services.model_adapter import ModelManager, TeammateModelAdapter
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


def test_verify_active_model_api(client):
    """Verifies that the /api/v1/model/verify endpoint successfully validates the active model."""
    res = client.post("/api/v1/model/verify", json={})
    assert res.status_code == 200
    data = res.get_json()
    assert data["verified"] is True
    assert data["status"] == "VERIFIED_COMPATIBLE"
    assert data["input_dimension"] in (78, 100)  # trustlab=78, bootstrap=100
    assert "inference_latency_ms" in data
    assert data["inference_latency_ms"] >= 0


def test_verify_custom_teammate_callable():
    """Tests verification of a teammate's custom Python model callable."""
    # Define a teammate anomaly function
    def custom_teammate_model(feat_vec):
        score = float(np.mean(feat_vec) * 0.5)
        errs = feat_vec * 0.1
        return score, errs

    result = ModelManager.verify_model(custom_teammate_model)
    assert result["verified"] is True
    assert result["status"] == "VERIFIED_COMPATIBLE"
    assert result["input_dimension"] == 78
    assert result["feature_errors_dim"] == 78
    assert "inference_latency_ms" in result


def test_verify_incompatible_model_detection():
    """Tests that an invalid or incompatible model fails verification with clear error."""
    # Model returns wrong dimension or broken output
    def broken_teammate_model(feat_vec):
        return "not_a_number", [1, 2]  # Wrong length (2 instead of 100)

    result = ModelManager.verify_model(broken_teammate_model)
    assert result["verified"] is False
    assert "error" in result


def test_teammate_model_hot_swapping(client):
    """Tests hot-swapping a teammate model into the live event processor and scoring an event."""
    proc = EventProcessor.get_instance()

    # Create teammate detector
    def teammate_detector(feat_vec):
        score = 8.5
        errs = np.ones(len(feat_vec), dtype=np.float32) * 0.085
        return score, errs

    with pytest.raises(PermissionError):      # the authoritative bundle is protected by default
        ModelManager.hot_swap_teammate_model(teammate_detector)
    swap_res = ModelManager.hot_swap_teammate_model(teammate_detector, version_tag="teammate-hot-swap-v1",
                                                    replace_authoritative=True)
    assert swap_res["status"] == "deployed"
    assert swap_res["verification"]["verified"] is True

    # Ingest event and verify it runs through the new teammate model
    # A flow record carrying CICFlowMeter columns (the 78-feature model's input schema).
    event_data = {
        "src_ip": "192.168.1.15", "dst_ip": "10.0.0.5", "src_port": 50000, "dst_port": 80,
        "protocol": "TCP", "bytes": 1024, "timestamp": 1600000100.0,
        **{name: proc.medians[name] for name in proc.feature_names[3:40]},
    }
    try:
        result = proc.ingest(event_data)
    finally:
        proc.reload_model()   # the singleton must go back to the authoritative bundle
    assert result is not None
    assert result["ai_processed"] is True
    assert result["anomaly_score"] is not None
    assert result["ai_error"] is None


def test_predict_single_flow(client):
    """Tests single flow prediction using the trained KitNET bundle."""
    # Valid flow payload
    flow = {
        "Src Port": 45000,
        "Dst Port": 443,
        "Protocol": 6,
        "Flow Duration": 100000,
        "Tot Fwd Pkts": 500,
        "Tot Bwd Pkts": 10,
        "TotLen Fwd Pkts": 5000000,
        "TotLen Bwd Pkts": 1000,
        "Flow Byts/s": 50000.0,
        "Flow Pkts/s": 500.0,
    }
    res = client.post("/api/v1/model/predict", json=flow)
    assert res.status_code == 200
    data = res.get_json()
    assert "anomaly_score" in data
    assert "threshold" in data
    assert "is_anomalous" in data
    assert "risk_level" in data
    assert "top_contributing_features" in data
    assert isinstance(data["top_contributing_features"], list)
    assert "detector_signals" in data
    assert isinstance(data["detector_signals"], list)
    assert "detector_count" in data
    assert data["model"] == "kitnet_trustlab" and data["bundle"] == "kitnet_trustlab_bundle"
    assert data["feature_count"] == 78 and data["threshold"] == 0.07018400015809657

    # Missing/empty body
    bad_res = client.post("/api/v1/model/predict", data="invalid json", content_type="application/json")
    assert bad_res.status_code == 400


def test_predict_batch_flows(client):
    """Tests batch flow prediction using the trained KitNET bundle."""
    flows = [
        {"Src Port": 80, "Dst Port": 12345, "Protocol": 6, "Flow Duration": 100},
        {"Src Port": 443, "Dst Port": 55555, "Protocol": 17, "Flow Duration": 999999},
    ]
    res = client.post("/api/v1/model/predict/batch", json={"flows": flows})
    assert res.status_code == 200
    batch = res.get_json()
    assert batch["total"] == 2
    assert "anomalous" in batch
    assert "normal" in batch
    assert "mean_score" in batch
    assert "max_score" in batch
    assert len(batch["results"]) == 2
    for r in batch["results"]:
        assert "anomaly_score" in r
        assert "is_anomalous" in r

    # Empty flows array
    empty_res = client.post("/api/v1/model/predict/batch", json={"flows": []})
    assert empty_res.status_code == 400

