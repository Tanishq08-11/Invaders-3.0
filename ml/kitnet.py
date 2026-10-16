"""
DEPRECATED for production - in-repo KitNET used by the legacy bootstrap/training path and its tests.
Production inference uses ml/trustlab_adapter.py (the authoritative 78-feature bundle).
"""
"""
KitNET Anomaly Detector Architecture
Mirsky et al., "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", NDSS 2018.

Implements the three-phase pipeline:
1. Feature Mapping (Correlation-based Clustering)
2. Ensemble Autoencoder & Output Autoencoder Training on Normal Traffic
3. Real-time Anomaly Scoring & Feature-Level Attribution
"""
from typing import List, Tuple, Dict, Any, Optional
import os
import pickle
import numpy as np
import torch

from ml.autoencoder import KitAutoencoder
from ml.clustering import FeatureMapper


class KitNET:
    """
    KitNET online / offline anomaly detector.
    Combines hierarchical feature clustering with an ensemble of small autoencoders
    and an output aggregator autoencoder.
    """
    def __init__(
        self,
        input_dim: int = 100,
        max_cluster_size: int = 10,
        hidden_ratio: float = 0.75,
        lr: float = 0.05,
        grace_fm: int = 300,
        grace_train: int = 1200
    ):
        self.input_dim = input_dim
        self.max_cluster_size = max_cluster_size
        self.hidden_ratio = hidden_ratio
        self.lr = lr
        self.grace_fm = grace_fm
        self.grace_train = grace_train

        self.feature_mapper = FeatureMapper(max_cluster_size=max_cluster_size)
        self.clusters: List[List[int]] = []
        self.ensemble: List[KitAutoencoder] = []
        self.output_ae: Optional[KitAutoencoder] = None

        # Normalization parameters learned from normal baseline
        self.norm_mean = np.zeros(input_dim, dtype=np.float32)
        self.norm_std = np.ones(input_dim, dtype=np.float32)

        # Baseline calibration statistics
        self.baseline_scores: List[float] = []
        self.baseline_mean: float = 0.0
        self.baseline_std: float = 1.0
        self.baseline_max: float = 0.0

        # State tracking
        self.count: int = 0
        self.phase: str = "FEATURE_MAPPING" # FEATURE_MAPPING -> TRAINING -> DETECTION
        self.fm_buffer: List[np.ndarray] = []

    def _normalize(self, x: np.ndarray) -> np.ndarray:
        return (x - self.norm_mean) / (self.norm_std + 1e-6)

    def _train_ensemble_step(self, x_norm: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Runs one forward/backward pass through each ensemble autoencoder.
        Returns: (ensemble_rmse_vector, feature_squared_errors)
        """
        ensemble_rmses = []
        feature_se = np.zeros(self.input_dim, dtype=np.float32)

        for ae, cluster in zip(self.ensemble, self.clusters):
            sub_x = x_norm[cluster]
            rmse, se_sub = ae.train_step(sub_x)
            ensemble_rmses.append(rmse)
            feature_se[cluster] = se_sub

        return np.array(ensemble_rmses, dtype=np.float32), feature_se

    def _eval_ensemble(self, x_norm: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Runs inference through ensemble autoencoders.
        Returns: (ensemble_rmse_vector, feature_squared_errors)
        """
        ensemble_rmses = []
        feature_se = np.zeros(self.input_dim, dtype=np.float32)

        for ae, cluster in zip(self.ensemble, self.clusters):
            sub_x = x_norm[cluster]
            rmse, se_sub = ae.evaluate(sub_x)
            ensemble_rmses.append(rmse)
            feature_se[cluster] = se_sub

        return np.array(ensemble_rmses, dtype=np.float32), feature_se

    def process(self, x: np.ndarray) -> Tuple[float, np.ndarray, str]:
        """
        Processes a single feature vector in streaming mode.
        Returns: (anomaly_score, per_feature_errors, current_phase)
        """
        self.count += 1

        # Phase 1: Feature Mapping
        if self.count <= self.grace_fm:
            self.fm_buffer.append(x)
            if self.count == self.grace_fm:
                self._finalize_feature_mapping()
                self.phase = "TRAINING"
            return 0.0, np.zeros(self.input_dim, dtype=np.float32), "FEATURE_MAPPING"

        # Phase 2: Ensemble & Output AE Training
        elif self.count <= (self.grace_fm + self.grace_train):
            x_norm = self._normalize(x)
            ens_rmses, feat_se = self._train_ensemble_step(x_norm)
            out_rmse, _ = self.output_ae.train_step(ens_rmses)
            self.baseline_scores.append(out_rmse)

            if self.count == (self.grace_fm + self.grace_train):
                self._finalize_baseline_calibration()
                self.phase = "DETECTION"

            return out_rmse, feat_se, "TRAINING"

        # Phase 3: Operational Detection
        else:
            self.phase = "DETECTION"
            x_norm = self._normalize(x)
            ens_rmses, feat_se = self._eval_ensemble(x_norm)
            out_rmse, _ = self.output_ae.evaluate(ens_rmses)
            return out_rmse, feat_se, "DETECTION"

    def _finalize_feature_mapping(self):
        """Fit clusters from buffered normal traffic."""
        X_fm = np.array(self.fm_buffer, dtype=np.float32)
        self.norm_mean = np.mean(X_fm, axis=0)
        self.norm_std = np.std(X_fm, axis=0)
        self.norm_std[self.norm_std < 1e-6] = 1.0

        self.clusters = self.feature_mapper.fit(X_fm)
        self.ensemble = [
            KitAutoencoder(input_dim=len(c), hidden_ratio=self.hidden_ratio, lr=self.lr)
            for c in self.clusters
        ]
        self.output_ae = KitAutoencoder(
            input_dim=len(self.clusters), hidden_ratio=self.hidden_ratio, lr=self.lr
        )
        self.fm_buffer.clear()

    def _finalize_baseline_calibration(self):
        """Compute baseline statistical parameters from training errors."""
        scores = np.array(self.baseline_scores, dtype=np.float32)
        self.baseline_mean = float(np.mean(scores))
        self.baseline_std = float(max(1e-4, np.std(scores)))
        self.baseline_max = float(np.max(scores))

    def fit_batch(self, X_normal: np.ndarray, epochs: int = 1):
        """
        Offline batch training on normal baseline dataset (e.g. BoT-IoT normal split).
        """
        N, D = X_normal.shape
        self.input_dim = D
        fm_size = min(self.grace_fm, max(50, N // 4))

        # 1. Feature Mapping
        X_fm = X_normal[:fm_size]
        self.norm_mean = np.mean(X_normal, axis=0)
        self.norm_std = np.std(X_normal, axis=0)
        self.norm_std[self.norm_std < 1e-6] = 1.0

        self.clusters = self.feature_mapper.fit(X_fm)
        self.ensemble = [
            KitAutoencoder(input_dim=len(c), hidden_ratio=self.hidden_ratio, lr=self.lr)
            for c in self.clusters
        ]
        self.output_ae = KitAutoencoder(
            input_dim=len(self.clusters), hidden_ratio=self.hidden_ratio, lr=self.lr
        )

        # 2. Train Ensemble and Output AEs on Normal Data
        X_train = X_normal[fm_size:]
        X_train_norm = self._normalize(X_train)
        self.baseline_scores = []

        for _ in range(epochs):
            for i in range(len(X_train_norm)):
                row = X_train_norm[i]
                ens_rmses, _ = self._train_ensemble_step(row)
                out_rmse, _ = self.output_ae.train_step(ens_rmses)
                self.baseline_scores.append(out_rmse)

        self._finalize_baseline_calibration()
        self.phase = "DETECTION"
        self.count = self.grace_fm + len(self.baseline_scores)

    def score(self, x: np.ndarray) -> Tuple[float, np.ndarray]:
        """
        Direct inference for a single feature vector in detection mode.
        Returns: (anomaly_score, feature_squared_errors)
        """
        if self.phase != "DETECTION" and len(self.ensemble) == 0:
            return 0.0, np.zeros(self.input_dim, dtype=np.float32)

        x_norm = self._normalize(x)
        ens_rmses, feat_se = self._eval_ensemble(x_norm)
        if self.output_ae is not None:
            out_rmse, _ = self.output_ae.evaluate(ens_rmses)
        else:
            out_rmse = float(np.mean(ens_rmses))
        return out_rmse, feat_se

    def save(self, filepath: str):
        """Save model state, clusters, parameters, and baseline calibration."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        ensemble_weights = [ae.state_dict() for ae in self.ensemble]
        output_ae_weights = self.output_ae.state_dict() if self.output_ae else None

        state = {
            "input_dim": self.input_dim,
            "max_cluster_size": self.max_cluster_size,
            "hidden_ratio": self.hidden_ratio,
            "lr": self.lr,
            "clusters": self.clusters,
            "norm_mean": self.norm_mean,
            "norm_std": self.norm_std,
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "baseline_max": self.baseline_max,
            "phase": self.phase,
            "count": self.count,
            "ensemble_weights": ensemble_weights,
            "output_ae_weights": output_ae_weights
        }
        with open(filepath, "wb") as f:
            pickle.dump(state, f)

    def load(self, filepath: str):
        """Load model state and restore PyTorch autoencoder weights."""
        with open(filepath, "rb") as f:
            state = pickle.load(f)

        self.input_dim = state["input_dim"]
        self.max_cluster_size = state["max_cluster_size"]
        self.hidden_ratio = state["hidden_ratio"]
        self.lr = state["lr"]
        self.clusters = state["clusters"]
        self.norm_mean = state["norm_mean"]
        self.norm_std = state["norm_std"]
        self.baseline_mean = state["baseline_mean"]
        self.baseline_std = state["baseline_std"]
        self.baseline_max = state["baseline_max"]
        self.phase = state["phase"]
        self.count = state["count"]

        # Rebuild ensemble
        self.ensemble = [
            KitAutoencoder(input_dim=len(c), hidden_ratio=self.hidden_ratio, lr=self.lr)
            for c in self.clusters
        ]
        for ae, w in zip(self.ensemble, state["ensemble_weights"]):
            ae.load_state_dict(w)
            ae.eval()

        if state["output_ae_weights"] and len(self.clusters) > 0:
            self.output_ae = KitAutoencoder(
                input_dim=len(self.clusters), hidden_ratio=self.hidden_ratio, lr=self.lr
            )
            self.output_ae.load_state_dict(state["output_ae_weights"])
            self.output_ae.eval()
