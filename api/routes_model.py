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
        "phase": kitnet.phase if kitnet else None,
        "input_dimension": kitnet.input_dim if kitnet else None,
        "num_clusters": len(kitnet.clusters) if kitnet else 0,
        "cluster_sizes": [len(c) for c in kitnet.clusters] if kitnet else [],
        "baseline_mean_error": round(kitnet.baseline_mean, 5) if kitnet else None,
        "baseline_std_error": round(kitnet.baseline_std, 5) if kitnet else None,
        "baseline_max_error": round(kitnet.baseline_max, 5) if kitnet else None,
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

    if checkpoint_name:
        target_path = os.path.join(Config.CHECKPOINTS_DIR, checkpoint_name)

    if target_path:
        verification = ModelManager.verify_model(target_path)
    else:
        if not proc.kitnet:
            return jsonify({
                "verified": False,
                "error": "No active model currently loaded in pipeline to verify"
            }), 400
        verification = ModelManager.verify_model(proc.kitnet)

    if deploy and verification.get("verified"):
        if target_path:
            ModelManager.hot_swap_teammate_model(target_path, version_tag=data.get("version_tag", "teammate-verified"))
        return jsonify({
            "message": "Model verified and successfully deployed to live pipeline!",
            "verification": verification,
            "status": "active"
        })

    return jsonify(verification), (200 if verification.get("verified") else 422)

