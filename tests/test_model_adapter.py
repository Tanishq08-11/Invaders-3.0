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
    assert data["input_dimension"] == 100
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
    assert result["input_dimension"] == 100
    assert result["feature_errors_dim"] == 100
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
        errs = np.ones(100, dtype=np.float32) * 0.085
        return score, errs

    swap_res = ModelManager.hot_swap_teammate_model(teammate_detector, version_tag="teammate-hot-swap-v1")
    assert swap_res["status"] == "deployed"
    assert swap_res["verification"]["verified"] is True

    # Ingest event and verify it runs through the new teammate model
    event_data = {
        "src_ip": "192.168.1.15",
        "dst_ip": "10.0.0.5",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": "TCP",
        "bytes": 1024,
        "timestamp": 1600000100.0
    }
    result = proc.ingest(event_data)
    assert result is not None
    assert result["ai_processed"] is True
    assert result["anomaly_score"] is not None
    assert result["ai_error"] is None
