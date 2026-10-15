"""
Unit Tests for Risk Engine and Explanation Engine (XAI)
"""
import pytest
import numpy as np
from datetime import datetime, timezone
from ml.risk_engine import RiskEngine
from ml.explanation_engine import ExplanationEngine


def test_risk_engine_normal_flow():
    engine = RiskEngine()
    flow = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",
        "dst_port": 80,
        "timestamp": datetime(2026, 10, 15, 14, 0, tzinfo=timezone.utc), # 2 PM Thursday (business hours)
        "length": 300
    }
    # Anomaly score very close to baseline mean
    eval_res = engine.evaluate(
        anomaly_score=0.05,
        flow_meta=flow,
        baseline_mean=0.05,
        baseline_std=0.02,
        baseline_max=0.10
    )

    assert eval_res["severity"] == "NORMAL"
    assert eval_res["is_threat"] is False
    assert eval_res["risk_score"] < 30.0


def test_risk_engine_exfiltration_threat():
    engine = RiskEngine()
    flow = {
        "src_ip": "192.168.1.105",
        "dst_ip": "198.51.100.88", # External IP
        "dst_port": 443,           # TLS
        "timestamp": datetime(2026, 10, 15, 23, 30, tzinfo=timezone.utc), # 11:30 PM (off-hours)
        "length": 1460             # Full MTU bulk frame
    }
    # Anomaly score 10 standard deviations above baseline
    eval_res = engine.evaluate(
        anomaly_score=0.45,
        flow_meta=flow,
        baseline_mean=0.05,
        baseline_std=0.02,
        baseline_max=0.10
    )

    assert eval_res["severity"] in ["HIGH", "CRITICAL"]
    assert eval_res["is_threat"] is True
    assert eval_res["risk_score"] >= 75.0
    assert eval_res["is_external_dst"] is True
    assert eval_res["off_hours"] is True


def test_explanation_engine_narrative_and_features():
    feature_names = [
        "host_pkt_rate_L5.0",
        "host_pkt_size_mean_L5.0",
        "channel_flow_rate_L1.0",
        "burst_velocity_L5.0",
        "flow_asymmetry_metric_L5.0"
    ]
    engine = ExplanationEngine(feature_names=feature_names)

    feature_errors = np.array([0.05, 0.10, 0.02, 0.85, 0.40], dtype=np.float32)
    flow = {
        "src_ip": "192.168.1.105",
        "dst_ip": "203.0.113.88",
        "dst_port": 443,
        "protocol": "TCP"
    }
    risk_eval = {
        "severity": "HIGH",
        "risk_score": 88.5,
        "off_hours": True,
        "is_external_dst": True
    }

    result = engine.explain(feature_errors, flow, risk_eval, top_k=3)
    assert "top_features" in result
    assert len(result["top_features"]) == 3

    # Top feature should be burst_velocity_L5.0 (index 3 with value 0.85)
    top_feat = result["top_features"][0]
    assert top_feat["feature_name"] == "burst_velocity_L5.0"
    assert top_feat["rank"] == 1
    assert top_feat["contribution_pct"] > 0

    # Check narrative
    narrative = result["explanation_text"]
    assert "192.168.1.105" in narrative
    assert "203.0.113.88" in narrative
    assert "HIGH" in narrative
    assert len(result["mitigation_steps"]) > 0
