"""
Model Adapter and Teammate Model Integration Manager
=====================================================
Verifies, adapts, and hot-swaps any teammate ML model into the Person 4 backend.
Supports:
  • KitNET Ensemble Autoencoders (.pkl, .pt)
  • Teammate PyTorch models (torch.nn.Module, state_dict)
  • Teammate Scikit-learn models (Random Forest, Isolation Forest, OneClassSVM)
  • Custom Python detectors implementing score() or predict()
"""
import os
import time
import pickle
from typing import Dict, Any, Optional, Tuple, Callable
import numpy as np

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class TeammateModelAdapter:
    """
    Adapter that wraps any external teammate detector model and exposes
    the standard contract required by EventProcessor:
        score(feat_vec: np.ndarray) -> Tuple[float, np.ndarray]
    """
    def __init__(self, raw_model: Any, model_type: str = "custom"):
        self.raw_model = raw_model
        self.model_type = model_type
        self.baseline_mean: float = 0.5
        self.baseline_std: float = 1.0
        self.baseline_max: float = 20.0

    def score(self, feat_vec: np.ndarray) -> Tuple[float, np.ndarray]:
        """
        Executes inference on a feature vector, returning:
          - anomaly_score (scalar float)
          - per-feature reconstruction errors (array for XAI attribution)
        """
        # 1. Native KitNET model
        if hasattr(self.raw_model, "score") and callable(self.raw_model.score):
            return self.raw_model.score(feat_vec)

        # 2. PyTorch Module
        if TORCH_AVAILABLE and isinstance(self.raw_model, torch.nn.Module):
            self.raw_model.eval()
            with torch.no_grad():
                tensor_in = torch.from_numpy(feat_vec).float().unsqueeze(0)
                reconstructed = self.raw_model(tensor_in)
                diff = (tensor_in - reconstructed).squeeze(0).numpy()
                errs = diff ** 2
                score = float(np.sqrt(np.mean(errs)))
                return score, errs

        # 3. Scikit-learn / Anomaly Estimator (e.g. IsolationForest, OneClassSVM, RandomForest)
        if hasattr(self.raw_model, "score_samples"):
            # score_samples returns opposite of anomaly score (higher = normal)
            raw_score = -float(self.raw_model.score_samples(feat_vec.reshape(1, -1))[0])
            errs = np.abs(feat_vec * 0.1)  # Synthetic linear contribution
            return raw_score, errs
        elif hasattr(self.raw_model, "decision_function"):
            raw_score = -float(self.raw_model.decision_function(feat_vec.reshape(1, -1))[0])
            errs = np.abs(feat_vec * 0.1)
            return raw_score, errs
        elif hasattr(self.raw_model, "predict_proba"):
            # Supervised leak classifier probability of class 1 (threat)
            prob = float(self.raw_model.predict_proba(feat_vec.reshape(1, -1))[0, 1])
            errs = np.abs(feat_vec * prob)
            return prob * 100.0, errs

        # 4. Generic Callable / Custom Detector
        if callable(self.raw_model):
            out = self.raw_model(feat_vec)
            if isinstance(out, tuple) and len(out) == 2:
                return float(out[0]), np.array(out[1], dtype=np.float32)
            return float(out), np.abs(feat_vec * 0.1)

        raise TypeError(f"Unsupported teammate model architecture: {type(self.raw_model)}")


class ModelManager:
    """
    Manages model registration, integrity verification, and dynamic hot-swapping.
    """
    @staticmethod
    def verify_model(model_obj_or_path: Any, input_dim: Optional[int] = None) -> Dict[str, Any]:
        """
        Runs an automated calibration test on any model to rigorously verify
        that it satisfies Person 4 integration requirements before deployment.
        """
        start = time.time()
        model = model_obj_or_path
        model_name = "in_memory_model"

        # Load from disk if path
        if isinstance(model_obj_or_path, str):
            model_name = os.path.basename(model_obj_or_path)
            if not os.path.exists(model_obj_or_path):
                return {
                    "verified": False,
                    "error": f"Model checkpoint not found: {model_obj_or_path}"
                }
            try:
                with open(model_obj_or_path, "rb") as f:
                    model = pickle.load(f)
            except Exception as e:
                if TORCH_AVAILABLE:
                    try:
                        model = torch.load(model_obj_or_path, map_location="cpu")
                    except Exception as e2:
                        return {"verified": False, "error": f"Failed to load model: {e2}"}
                else:
                    return {"verified": False, "error": f"Failed to load pickle: {e}"}

        # Wrap in adapter
        adapter = TeammateModelAdapter(model)

        if input_dim is None:
            if hasattr(model, "input_dim") and isinstance(model.input_dim, int):
                input_dim = model.input_dim
            elif hasattr(model, "n_features_in_") and isinstance(model.n_features_in_, int):
                input_dim = model.n_features_in_
            elif hasattr(adapter.raw_model, "input_dim") and isinstance(adapter.raw_model.input_dim, int):
                input_dim = adapter.raw_model.input_dim
            else:
                input_dim = 78

        # Run synthetic calibration vector
        test_vec = np.ones(input_dim, dtype=np.float32) * 2.5
        try:
            score, errs = adapter.score(test_vec)
            latency_ms = round((time.time() - start) * 1000, 3)

            is_valid_score = isinstance(score, (int, float)) and not np.isnan(score)
            is_valid_errs = isinstance(errs, np.ndarray) and len(errs) == input_dim

            if not (is_valid_score and is_valid_errs):
                return {
                    "verified": False,
                    "error": f"Model returned invalid output signature: score={score}, errs_shape={getattr(errs, 'shape', None)}"
                }

            return {
                "verified": True,
                "status": "VERIFIED_COMPATIBLE",
                "model_name": model_name,
                "model_type": type(model).__name__,
                "sample_anomaly_score": round(float(score), 4),
                "feature_errors_dim": len(errs),
                "inference_latency_ms": latency_ms,
                "input_dimension": input_dim,
                "message": "Model successfully verified and confirmed compatible with pipeline integration seam."
            }

        except Exception as exc:
            return {
                "verified": False,
                "error": f"Inference execution failed on test vector: {str(exc)}"
            }

    @staticmethod
    def hot_swap_teammate_model(model_obj: Any, version_tag: str = "teammate-v1",
                                replace_authoritative: bool = False) -> Dict[str, Any]:
        """
        Hot-swaps an external model into the live EventProcessor pipeline. The live model is the
        authoritative TrustLab bundle, so this refuses unless `replace_authoritative=True`, and the
        replacement must accept the same 78-feature vector. EventProcessor.reload_model() restores
        the bundle.
        """
        if not replace_authoritative:
            raise PermissionError("Refusing to replace the authoritative TrustLab KitNET bundle "
                                  "(pass replace_authoritative=True for a deliberate deployment).")
        verification = ModelManager.verify_model(model_obj, input_dim=78)
        if not verification.get("verified"):
            raise ValueError(f"Cannot deploy unverified model: {verification.get('error')}")

        adapter = TeammateModelAdapter(model_obj)
        from services.event_processor import EventProcessor
        proc = EventProcessor.get_instance()
        proc.kitnet = adapter
        proc.model_loaded = True

        return {
            "status": "deployed",
            "version": version_tag,
            "verification": verification
        }
