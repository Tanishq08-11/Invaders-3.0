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
        "input_dimension": getattr(kitnet, "input_dim", None) if kitnet else None,
        "model": "kitnet_trustlab_bundle",
        "anomaly_threshold": proc.threshold,
        "feature_names": proc.feature_names,
        "bundle_sha256": proc.bundle_sha256,
        "detector": proc.detector_status(),
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
    # The live detector is the fixed, pre-trained TrustLab bundle; it is never retrained here.
    return jsonify({"error": "Training is disabled: the live detector is the authoritative pre-trained "
                             "TrustLab KitNET bundle (ml/kitnet_trustlab_bundle.pkl), which must not be retrained."}), 409


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
        "message": ("Legacy z-score thresholds updated. They do NOT affect detection: the TrustLab KitNET "
                    "decision threshold is fixed by the bundle."),
        "trustlab_threshold": proc.threshold,
        "thresholds": {
            "z_low": risk_engine.z_low,
            "z_med": risk_engine.z_med,
            "z_high": risk_engine.z_high,
            "z_crit": risk_engine.z_crit
        }
    })


@bp_model.route("/features", methods=["GET"])
def list_features():
    """Returns the 78 TrustLab model features (bundle order) and their cluster mapping."""
    proc = EventProcessor.get_instance()
    clusters = getattr(proc.kitnet, "clusters", []) or []
    cluster_lookup = {f_idx: c_idx for c_idx, cluster in enumerate(clusters) for f_idx in cluster}
    feature_list = [{
        "index": idx, "name": name, "display_name": name, "cluster_id": cluster_lookup.get(idx),
        "training_median": proc.medians.get(name),
        "description": "Time encoding of the flow start" if name in ("HourSin", "HourCos", "DaySin", "DayCos")
                       else "CICFlowMeter flow feature",
    } for idx, name in enumerate(proc.feature_names)]
    return jsonify({"total_features": len(feature_list), "total_clusters": len(clusters), "features": feature_list})


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
        if data.get("replace_authoritative_model") is not True:
            return jsonify({"verified": True, "deployed": False, "verification": verification,
                            "error": "The live model is the authoritative TrustLab bundle; deployment requires "
                                     "replace_authoritative_model=true."}), 409
        if target_path:
            ModelManager.hot_swap_teammate_model(target_path, version_tag=data.get("version_tag", "teammate-verified"),
                                                 replace_authoritative=True)
        return jsonify({
            "message": "Model verified and successfully deployed to live pipeline!",
            "verification": verification,
            "status": "active"
        })

    return jsonify(verification), (200 if verification.get("verified") else 422)


def _ml_result(model, flow):
    """One flow through the SAME canonical builder + authoritative bundle the live pipeline uses."""
    import numpy as np
    out = model.predict(flow, tz_name=Config.TRUSTLAB_TIMEZONE)
    fv, errors, score = out["vector"], out["feature_errors"], out["anomaly_score"]
    top = [{"index": int(i), "name": fv.names[i], "error": round(float(errors[i]), 6),
            "input_value": round(float(fv.values[i]), 6), "value_source": fv.sources[fv.names[i]]}
           for i in np.argsort(errors)[::-1][:10] if errors[i] > 0]
    ratio = score / model.threshold if model.threshold > 0 else 0.0
    return out, top, ratio, fv


def _authoritative_model():
    from ml.trustlab_adapter import TrustLabKitNET
    proc = EventProcessor.get_instance()
    if not proc.model_loaded or not isinstance(proc.kitnet, TrustLabKitNET):
        return None
    return proc.kitnet


@bp_model.route("/predict", methods=["POST"])
def predict():
    """
    Score one CICFlowMeter-named flow with the authoritative TrustLab bundle, through the same
    canonical 78-feature builder as the live pipeline (unmeasured features -> bundle medians,
    time features from "Timestamp"). Rule detectors (D1-D28) need entity history and run in the
    event pipeline (POST /api/v1/events), so they are not evaluated here.
    """
    from ml.risk_engine import ai_risk_from_score, risk_level as level_of
    model = _authoritative_model()
    if model is None:
        return jsonify({"error": "TrustLab KitNET model not loaded"}), 503
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON flow object"}), 400
    out, top, ratio, fv = _ml_result(model, data)
    ai_risk = ai_risk_from_score(out["anomaly_score"], model.threshold)
    return jsonify({
        "anomaly_score": round(out["anomaly_score"], 8),
        "threshold": model.threshold,
        "is_anomaly": out["is_anomaly"],
        "is_anomalous": out["is_anomaly"],
        "risk_level": level_of(ai_risk),
        "ai_risk_score": ai_risk,
        "score_to_threshold_ratio": round(ratio, 4),
        "top_contributing_features": top,
        "feature_coverage": fv.coverage(),
        "detector_signals": [],
        "detector_count": 0,
        "detector_note": "D1-D28 run in the event pipeline (POST /api/v1/events), which has entity history.",
        "model": "kitnet_trustlab",
        "bundle": "kitnet_trustlab_bundle",      # previous value of "model" (compatibility)
        "feature_count": 78,
        "input_dimension": model.input_dim,
        "clusters": len(model.clusters),
    })


@bp_model.route("/predict/batch", methods=["POST"])
def predict_batch():
    """Batch version of /predict - same builder, same model. {"flows": [...], "limit": 500}."""
    import numpy as np
    model = _authoritative_model()
    if model is None:
        return jsonify({"error": "TrustLab KitNET model not loaded"}), 503
    data = request.get_json(silent=True) or {}
    flows = data.get("flows", [])
    if not isinstance(flows, list) or len(flows) == 0:
        return jsonify({"error": "Request body must contain a non-empty 'flows' array"}), 400
    try:
        limit = max(1, min(int(data.get("limit", 500)), 1000))
    except (TypeError, ValueError):
        return jsonify({"error": "limit must be an integer"}), 400
    results, scores = [], []
    for flow in flows[:limit]:
        if not isinstance(flow, dict):
            results.append({"error": "Each flow must be a JSON object"})
            continue
        out, top, _, fv = _ml_result(model, flow)
        scores.append(out["anomaly_score"])
        results.append({"anomaly_score": round(out["anomaly_score"], 8), "is_anomaly": out["is_anomaly"],
                        "is_anomalous": out["is_anomaly"], "top_features": top[:3],
                        "imputed_features": fv.coverage()["imputed"]})
    anomalous = sum(1 for r in results if r.get("is_anomaly"))
    return jsonify({
        "total": len(results), "anomalous": anomalous, "normal": len(scores) - anomalous,
        "threshold": model.threshold, "model": "kitnet_trustlab", "feature_count": 78,
        "mean_score": round(float(np.mean(scores)), 8) if scores else None,
        "max_score": round(float(np.max(scores)), 8) if scores else None,
        "results": results,
    })


@bp_model.route("/health", methods=["GET"])
def model_health():
    """Authoritative model status (no filesystem paths)."""
    from ml.trustlab_adapter import TrustLabKitNET
    proc = EventProcessor.get_instance()
    m = proc.kitnet if isinstance(proc.kitnet, TrustLabKitNET) else None
    loaded = bool(proc.model_loaded and m is not None)
    return jsonify({
        "model": "kitnet_trustlab",
        "loaded": loaded,
        "feature_count": len(m.feature_names) if m else 0,
        "threshold": m.threshold if m else None,
        "fm_grace_period": getattr(m, "fm_grace_period", None),
        "ad_grace_period": getattr(m, "ad_grace_period", None),
        "hyperparameters": getattr(m, "hyperparameters", None),
        "bundle_sha256": proc.bundle_sha256,
    }), (200 if loaded else 503)
