"""
TrustLab KitNET Bundle Adapter
===============================
Loads kitnet_trustlab_bundle.pkl (Mirsky's original KitNET format with
numpy-based dA denoising autoencoders) and exposes the standard interface
that EventProcessor and ModelAdapter expect:

    adapter.score(feat_vec_78d) → (rmse_float, per_feature_errors_78d)

The bundle was trained on 78 CICFlowMeter-style features (74 flow +
4 timestamp: HourSin, HourCos, DaySin, DayCos) and MUST NOT be retrained,
modified, or have its input schema altered.

Architecture inside the bundle:
  • 28 ensemble dA autoencoders (each over a cluster of feature indices)
  • 1 output dA autoencoder (input = 28 ensemble RMSEs → global RMSE)
  • Per-autoencoder min/max normalization arrays (norm_min, norm_max)
  • Median imputation dict for missing values
  • Threshold: 0.070184 (flows above this are anomalous)
"""
import math
import os
import pickle
import sys
import types
import logging
from typing import Dict, List, Optional, Tuple, Any

import numpy as np

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stub classes so pickle can deserialise the Mirsky KitNET objects
# without requiring the original KitNET / dA / corClust packages.
# ---------------------------------------------------------------------------
_STUB_MODULES = ("KitNET", "corClust", "dA", "nnetwork", "AfterImage")
_STUB_CLASSES = (
    "KitNET", "corClust", "dA", "dA_params",
    "nnetwork", "AfterImage", "incStatDB", "incStat", "incStatCov",
)


class _PickleStub:
    """Generic object that restores arbitrary __dict__ state from the pickle stream."""
    def __init__(self, *args, **kwargs):
        self.__dict__.update(kwargs)

    def __setstate__(self, state):
        if isinstance(state, dict):
            self.__dict__.update(state)


def _install_stubs():
    """Register fake modules/classes so pickle.load succeeds."""
    for mod_name in _STUB_MODULES:
        if mod_name in sys.modules:
            continue
        m = types.ModuleType(mod_name)
        for cls_name in _STUB_CLASSES:
            cls = type(cls_name, (_PickleStub,), {
                "__module__": mod_name,
                "__qualname__": cls_name,
            })
            setattr(m, cls_name, cls)
        sys.modules[mod_name] = m


# ---------------------------------------------------------------------------
# Pure-numpy dA forward pass (replicates Mirsky's dA.execute without torch)
# ---------------------------------------------------------------------------
def _sigmoid(x: np.ndarray) -> np.ndarray:
    """Numerically stable sigmoid."""
    x_clipped = np.clip(x, -500.0, 500.0)
    return np.where(
        x_clipped >= 0,
        1.0 / (1.0 + np.exp(-x_clipped)),
        np.exp(x_clipped) / (1.0 + np.exp(x_clipped)),
    )


def _da_execute(ae, x: np.ndarray) -> Tuple[float, np.ndarray]:
    """
    Run one forward pass through a Mirsky dA autoencoder.

    ae attributes used:
      .norm_min, .norm_max   — per-feature min/max arrays for [0,1] normalization
      .W, .hbias             — encoder weights/biases
      .W_prime, .vbias       — decoder weights/biases

    Returns (RMSE, per-feature squared errors).
    """
    norm_min = np.asarray(ae.norm_min, dtype=np.float64).ravel()
    norm_max = np.asarray(ae.norm_max, dtype=np.float64).ravel()
    denom = norm_max - norm_min
    denom[denom < 1e-10] = 1e-10
    x_norm = (x - norm_min) / denom

    W = np.asarray(ae.W, dtype=np.float64)
    hbias = np.asarray(ae.hbias, dtype=np.float64).ravel()
    W_prime = np.asarray(ae.W_prime, dtype=np.float64)
    vbias = np.asarray(ae.vbias, dtype=np.float64).ravel()

    # encode
    h = _sigmoid(x_norm @ W + hbias)
    # decode
    x_hat = _sigmoid(h @ W_prime + vbias)

    se = (x_norm - x_hat) ** 2
    rmse = float(np.sqrt(np.mean(se)))
    return rmse, se.astype(np.float32)


# ---------------------------------------------------------------------------
# TrustLabKitNET — the adapter class
# ---------------------------------------------------------------------------
class TrustLabKitNET:
    """
    Drop-in replacement for the project's KitNET class, backed by the
    pre-trained trustlab bundle.  Exposes:
      .score(x_78d)  → (global_rmse, feature_errors_78d)
      .phase         → always "DETECTION"
      .baseline_mean / .baseline_std / .baseline_max  (from threshold)
      .input_dim     → 78
      .clusters      → list of 28 index lists
    """

    def __init__(self):
        self.phase = "DETECTION"
        self.input_dim: int = 78
        self.feature_names: List[str] = []
        self.timestamp_features: List[str] = []
        self.metadata_columns: List[str] = []
        self.medians: Dict[str, float] = {}
        self.threshold: float = 0.070184

        # Ensemble
        self.clusters: List[List[int]] = []
        self.ensemble: list = []        # list of dA stub objects
        self.output_ae = None           # dA stub object

        # Baseline stats derived from threshold
        self.baseline_mean: float = 0.0
        self.baseline_std: float = 1.0
        self.baseline_max: float = 0.0

    # ------------------------------------------------------------------ load
    def load_bundle(self, bundle_path: str):
        """Load the pre-trained trustlab bundle pickle."""
        _install_stubs()

        with open(bundle_path, "rb") as f:
            bundle = pickle.load(f)

        if not isinstance(bundle, dict) or "model" not in bundle:
            raise ValueError(f"Invalid trustlab bundle: expected dict with 'model' key, got {type(bundle)}")

        self.feature_names = list(bundle["feature_names"])          # 78 names
        self.timestamp_features = list(bundle.get("timestamp_features", []))
        self.metadata_columns = list(bundle.get("metadata_columns", []))
        self.medians = dict(bundle.get("medians", {}))
        self.threshold = float(bundle.get("threshold", 0.070184))
        self.input_dim = len(self.feature_names)                    # 78

        model = bundle["model"]
        self.clusters = [list(c) for c in model.v]                  # 28 clusters
        self.ensemble = list(model.ensembleLayer)                   # 28 dA objects
        self.output_ae = model.outputLayer                          # 1 dA object

        # Derive baseline calibration from the threshold.
        # The trainer computed threshold as the RMSE at a chosen percentile;
        # we set baseline_mean ≈ threshold/2, std so that threshold ≈ mean + 3σ.
        self.baseline_mean = self.threshold * 0.35
        self.baseline_std = max(1e-6, (self.threshold - self.baseline_mean) / 3.5)
        self.baseline_max = self.threshold * 2.0

        log.info(
            "[TrustLabKitNET] Loaded: %d features, %d clusters, threshold=%.6f",
            self.input_dim, len(self.clusters), self.threshold,
        )

    # ------------------------------------------------------------------ score
    def score(self, x: np.ndarray) -> Tuple[float, np.ndarray]:
        """
        Run inference on one 78-D feature vector.

        Returns:
          anomaly_score  — global RMSE from the output autoencoder
          feature_errors — 78-D array of per-feature squared reconstruction errors
        """
        x = np.asarray(x, dtype=np.float64).ravel()
        if len(x) != self.input_dim:
            raise ValueError(f"Expected {self.input_dim}-D input, got {len(x)}-D")

        feature_se = np.zeros(self.input_dim, dtype=np.float32)
        ensemble_rmses = []

        for ae, cluster_indices in zip(self.ensemble, self.clusters):
            sub_x = x[cluster_indices]
            rmse, se_sub = _da_execute(ae, sub_x)
            ensemble_rmses.append(rmse)
            for i, idx in enumerate(cluster_indices):
                feature_se[idx] = se_sub[i]

        # Output autoencoder: 28-D → global RMSE
        ens_vec = np.array(ensemble_rmses, dtype=np.float64)
        global_rmse, _ = _da_execute(self.output_ae, ens_vec)

        return float(global_rmse), feature_se

    # ------------------------------------------------------------------ helpers
    def impute(self, flow_dict: Dict[str, Any]) -> np.ndarray:
        """
        Build the 78-D feature vector from a flow dictionary,
        imputing missing values with the bundle's median.
        """
        vec = np.zeros(self.input_dim, dtype=np.float64)
        for i, fname in enumerate(self.feature_names):
            raw = flow_dict.get(fname)
            if raw is not None:
                try:
                    vec[i] = float(raw)
                except (TypeError, ValueError):
                    vec[i] = self.medians.get(fname, 0.0)
            else:
                vec[i] = self.medians.get(fname, 0.0)
        # Replace NaN/Inf with medians
        for i in range(self.input_dim):
            if not np.isfinite(vec[i]):
                vec[i] = self.medians.get(self.feature_names[i], 0.0)
        return vec

    def is_anomalous(self, score: float) -> bool:
        """Returns True if the anomaly score exceeds the trained threshold."""
        return score > self.threshold


# ---------------------------------------------------------------------------
# Module-level convenience: load the bundle once
# ---------------------------------------------------------------------------
_DEFAULT_BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "kitnet_trustlab_bundle.pkl")
_instance: Optional[TrustLabKitNET] = None


def get_trustlab_model(bundle_path: Optional[str] = None) -> TrustLabKitNET:
    """Return the singleton TrustLabKitNET model, loading on first call."""
    global _instance
    if _instance is None:
        _instance = TrustLabKitNET()
        path = bundle_path or _DEFAULT_BUNDLE_PATH
        if os.path.isfile(path):
            _instance.load_bundle(path)
            log.info("[TrustLabKitNET] Loaded model from %s", path)
        else:
            log.warning("[TrustLabKitNET] Bundle not found at %s — model not loaded", path)
    return _instance
