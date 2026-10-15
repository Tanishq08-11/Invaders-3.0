"""
Model Management API Blueprint
Provides endpoints to inspect KitNET model state, trigger baseline training,
fine-tune detection thresholds, and explore feature clusters.
"""
import os
from flask import Blueprint, request, jsonify
from config import Config
from core.models import ModelVersion
from services.event_processor import EventProcessor
from services.training_service import TrainingService
from services.model_adapter import ModelManager

bp_model = Blueprint("model", __name__, url_prefix="/api/v1/model")


@bp_model.route("/status", methods=["GET"])
def model_status():
    """Inspects the active KitNET detector and baseline parameters."""
    proc = EventProcessor.get_instance()
    kitnet = proc.kitnet
    active_baseline = ModelVersion.query.filter_by(is_active=True).first()

    return jsonify({
        "is_model_loaded": proc.model_loaded,
        "phase": getattr(kitnet, "phase", "active") if kitnet else None,
        "input_dimension": getattr(kitnet, "input_dim", 100) if kitnet else None,
        "num_clusters": len(getattr(kitnet, "clusters", [])) if kitnet else 0,
        "cluster_sizes": [len(c) for c in getattr(kitnet, "clusters", [])] if kitnet else [],
        "baseline_mean_error": round(getattr(kitnet, "baseline_mean", 0.0), 5) if kitnet else None,
        "baseline_std_error": round(getattr(kitnet, "baseline_std", 1.0), 5) if kitnet else None,
        "baseline_max_error": round(getattr(kitnet, "baseline_max", 10.0), 5) if kitnet else None,
        "active_baseline_meta": active_baseline.to_dict() if active_baseline else None,
        "thresholds": {
            "z_low": proc.risk_engine.z_low,
            "z_med": proc.risk_engine.z_med,
            "z_high": proc.risk_engine.z_high,
            "z_crit": proc.risk_engine.z_crit
        } if proc.risk_engine else None
    })


@bp_model.route("/train", methods=["POST"])
def trigger_training():
    """
    Triggers baseline training on BoT-IoT normal dataset (or custom uploaded CSV).
    Workflow: Normal Traffic -> Kitsune AfterImage Extractor -> KitNET Training -> Baseline Calibration.
    """
    data = request.get_json(silent=True) or {}
    dataset_name = data.get("dataset_name", "botiot_normal_train.csv")
    csv_path = os.path.join(Config.DATA_DIR, dataset_name)
    epochs = int(data.get("epochs", 1))
    max_rows = data.get("max_rows")
    if max_rows is not None:
        max_rows = int(max_rows)

    if not os.path.exists(csv_path):
        return jsonify({"error": f"Training dataset not found: {csv_path}"}), 404

    trainer = TrainingService()
    try:
        train_result = trainer.train_baseline_from_csv(
            csv_path=csv_path,
            epochs=epochs,
            max_rows=max_rows
        )
        # Reload model into EventProcessor
        proc = EventProcessor.get_instance()
        proc.reload_model()
        if train_result.get("model_version_id"):
            proc.set_active_model_version(train_result["model_version_id"])

        return jsonify({
            "message": "KitNET baseline successfully trained and calibrated!",
            "details": train_result
        })
    except Exception as e:
        return jsonify({"error": f"Training failed: {str(e)}"}), 500


@bp_model.route("/thresholds", methods=["POST"])
def update_thresholds():
    """Dynamically updates risk engine sensitivity thresholds."""
    data = request.get_json(silent=True) or {}
    proc = EventProcessor.get_instance()
    risk_engine = proc.risk_engine

    if not risk_engine:
        return jsonify({"error": "Risk engine not initialized"}), 500

    if "z_low" in data:
        risk_engine.z_low = float(data["z_low"])
    if "z_med" in data:
        risk_engine.z_med = float(data["z_med"])
    if "z_high" in data:
        risk_engine.z_high = float(data["z_high"])
    if "z_crit" in data:
        risk_engine.z_crit = float(data["z_crit"])

    return jsonify({
        "message": "Detection thresholds updated successfully",
        "thresholds": {
            "z_low": risk_engine.z_low,
            "z_med": risk_engine.z_med,
            "z_high": risk_engine.z_high,
            "z_crit": risk_engine.z_crit
        }
    })


@bp_model.route("/features", methods=["GET"])
def list_features():
    """Returns the 100 AfterImage feature catalog and active cluster mappings."""
    proc = EventProcessor.get_instance()
    feature_names = proc.extractor.get_feature_names()
    clusters = proc.kitnet.clusters if proc.kitnet else []

    # Map feature index to cluster index
    cluster_lookup = {}
    for c_idx, cluster in enumerate(clusters):
        for f_idx in cluster:
            cluster_lookup[f_idx] = c_idx

    feature_list = []
    for idx, name in enumerate(feature_names):
        info = proc.explanation_engine._lookup_feature_info(name)
        feature_list.append({
            "index": idx,
            "name": name,
            "display_name": info["display"],
            "cluster_id": cluster_lookup.get(idx, 0),
            "description": info["desc"]
        })

    return jsonify({
        "total_features": len(feature_list),
        "total_clusters": len(clusters),
        "features": feature_list
    })


@bp_model.route("/verify", methods=["POST"])
def verify_model():
    """
    Rigorously verifies model integration compatibility with Person 4 pipeline.
    Tests input dimensions (100-D), output signature, score validity, and inference latency.
    Can verify:
      1. Currently active in-memory model (default)
      2. Uploaded / on-disk checkpoint (.pkl, .pt)
    Optionally hot-swaps model into live pipeline if `deploy: true`.
    """
    data = request.get_json(silent=True) or {}
    proc = EventProcessor.get_instance()

    target_path = data.get("model_path")
    checkpoint_name = data.get("checkpoint_name")
    deploy = bool(data.get("deploy", False))
    input_dim = data.get("input_dim")

    if checkpoint_name:
        target_path = os.path.join(Config.CHECKPOINTS_DIR, checkpoint_name)

    if target_path:
        verification = ModelManager.verify_model(target_path, input_dim=input_dim)
    else:
        if not proc.kitnet:
            return jsonify({
                "verified": False,
                "error": "No active model currently loaded in pipeline to verify"
            }), 400
        verification = ModelManager.verify_model(proc.kitnet, input_dim=input_dim)

    if deploy and verification.get("verified"):
        if target_path:
            ModelManager.hot_swap_teammate_model(target_path, version_tag=data.get("version_tag", "teammate-verified"))
        return jsonify({
            "message": "Model verified and successfully deployed to live pipeline!",
            "verification": verification,
            "status": "active"
        })

    return jsonify(verification), (200 if verification.get("verified") else 422)


@bp_model.route("/predict", methods=["POST"])
def predict():
    """
    Run KitNET anomaly detection on a single network flow.
    Accepts a JSON flow dict with CICFlowMeter-style feature names.
    Missing features are imputed with the trained medians.

    Returns:
      - anomaly_score, threshold, is_anomalous
      - top_contributing_features (XAI attribution from reconstruction errors)
      - risk_level (NORMAL / LOW / MEDIUM / HIGH / CRITICAL)
    """
    from ml.trustlab_adapter import get_trustlab_model
    import numpy as np

    model = get_trustlab_model()
    if not model.feature_names:
        return jsonify({"error": "TrustLab KitNET model not loaded"}), 503

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON flow object"}), 400

    # Build 78-D feature vector (median-imputed)
    feat_vec = model.impute(data)
    score_val, feat_errors = model.score(feat_vec)
    is_anomalous = model.is_anomalous(score_val)

    # Top contributing features (XAI)
    top_k = min(10, model.input_dim)
    top_indices = np.argsort(feat_errors)[-top_k:][::-1]
    top_features = [
        {
            "index": int(idx),
            "name": model.feature_names[idx],
            "error": round(float(feat_errors[idx]), 6),
            "input_value": round(float(feat_vec[idx]), 6),
        }
        for idx in top_indices
        if feat_errors[idx] > 0
    ]

    # Risk level based on score vs threshold
    ratio = score_val / model.threshold if model.threshold > 0 else 0.0
    if ratio < 0.5:
        risk_level = "NORMAL"
    elif ratio < 1.0:
        risk_level = "LOW"
    elif ratio < 2.0:
        risk_level = "MEDIUM"
    elif ratio < 5.0:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # D1-D21 secondary detection layer (independent of 78-D model features)
    detector_signals = []
    try:
        from services.detection.detectors import all_detectors
        from services.detection.engine import DetectionContext
        from services.detection.features import EventFeatures
        from services.detection.base import TRIGGERED

        f = EventFeatures(
            event_type="network_record",
            event_uuid="FLOW-PREDICT",
            ts=float(data.get("Timestamp", data.get("timestamp", 0.0)) or 0.0),
            src_ip=str(data.get("Src IP", data.get("src_ip", "0.0.0.0"))),
            dst_ip=str(data.get("Dst IP", data.get("dst_ip", "0.0.0.0"))),
            src_port=int(data.get("Src Port", data.get("src_port", 0)) or 0),
            dst_port=int(data.get("Dst Port", data.get("dst_port", 0)) or 0),
            protocol=str(data.get("Protocol", data.get("protocol", "TCP"))),
            outbound_bytes=float(data.get("TotLen Fwd Pkts", data.get("bytes", 0)) or 0),
            inbound_bytes=float(data.get("TotLen Bwd Pkts", 0) or 0),
            outbound_packets=float(data.get("Tot Fwd Pkts", 1) or 1),
            inbound_packets=float(data.get("Tot Bwd Pkts", 0) or 0),
            duration=float(data.get("Flow Duration", 0.0) or 0.0),
            completed=True,
        )
        ctx = DetectionContext(event=None, features=f, now=float(f.ts or 0.0))
        for det in all_detectors():
            if "network_record" in det.event_types or "network_flow" in det.event_types:
                try:
                    res = det.evaluate(ctx)
                    if res.status == TRIGGERED:
                        detector_signals.append({
                            "detector_id": det.id,
                            "name": det.name,
                            "severity": res.severity,
                            "score": res.score,
                            "reason": res.reason,
                        })
                except Exception:
                    pass
    except Exception:
        pass

    return jsonify({
        "anomaly_score": round(score_val, 8),
        "threshold": round(model.threshold, 8),
        "is_anomalous": is_anomalous,
        "risk_level": risk_level,
        "score_to_threshold_ratio": round(ratio, 4),
        "top_contributing_features": top_features,
        "detector_signals": detector_signals,
        "detector_count": len(detector_signals),
        "model": "kitnet_trustlab_bundle",
        "input_dimension": model.input_dim,
        "clusters": len(model.clusters),
    })


@bp_model.route("/predict/batch", methods=["POST"])
def predict_batch():
    """
    Run KitNET anomaly detection on a batch of network flows.
    Accepts: {"flows": [<flow_dict>, ...], "limit": 500}
    Returns per-flow results plus aggregate statistics.
    """
    from ml.trustlab_adapter import get_trustlab_model
    import numpy as np

    model = get_trustlab_model()
    if not model.feature_names:
        return jsonify({"error": "TrustLab KitNET model not loaded"}), 503

    data = request.get_json(silent=True) or {}
    flows = data.get("flows", [])
    if not isinstance(flows, list) or len(flows) == 0:
        return jsonify({"error": "Request body must contain a non-empty 'flows' array"}), 400

    limit = min(int(data.get("limit", 500)), 1000)
    flows = flows[:limit]

    results = []
    anomalous_count = 0
    scores = []

    for flow in flows:
        if not isinstance(flow, dict):
            results.append({"error": "Each flow must be a JSON object"})
            continue

        feat_vec = model.impute(flow)
        score_val, feat_errors = model.score(feat_vec)
        is_anom = model.is_anomalous(score_val)
        if is_anom:
            anomalous_count += 1
        scores.append(score_val)

        top_3 = np.argsort(feat_errors)[-3:][::-1]
        top_feats = [
            {"name": model.feature_names[int(i)], "error": round(float(feat_errors[i]), 6)}
            for i in top_3 if feat_errors[i] > 0
        ]

        results.append({
            "anomaly_score": round(score_val, 8),
            "is_anomalous": is_anom,
            "top_features": top_feats,
        })

    return jsonify({
        "total": len(results),
        "anomalous": anomalous_count,
        "normal": len(results) - anomalous_count,
        "threshold": round(model.threshold, 8),
        "mean_score": round(float(np.mean(scores)), 8) if scores else None,
        "max_score": round(float(np.max(scores)), 8) if scores else None,
        "results": results,
    })

