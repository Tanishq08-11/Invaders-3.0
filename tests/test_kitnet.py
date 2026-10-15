"""
Unit Tests for KitNET Architecture: Feature Mapper, Ensemble Autoencoders, and Detection
"""
import os
import tempfile
import pytest
import numpy as np
from ml.autoencoder import KitAutoencoder
from ml.clustering import FeatureMapper
from ml.kitnet import KitNET


def test_autoencoder_forward_and_train():
    ae = KitAutoencoder(input_dim=8, hidden_ratio=0.75, lr=0.05)
    sample = np.random.randn(8).astype(np.float32)

    rmse_init, se_init = ae.evaluate(sample)
    assert isinstance(rmse_init, float)
    assert se_init.shape == (8,)

    # Train step
    rmse_step, _ = ae.train_step(sample)
    assert rmse_step >= 0.0


def test_feature_mapper_clustering():
    mapper = FeatureMapper(max_cluster_size=5)
    # Generate 50 samples of 12 features with some correlations
    np.random.seed(42)
    base = np.random.randn(50, 1)
    col1 = base + np.random.randn(50, 1) * 0.1
    col2 = base * 2.0 + np.random.randn(50, 1) * 0.1
    noise = np.random.randn(50, 10)
    X = np.hstack([col1, col2, noise]).astype(np.float32)

    clusters = mapper.fit(X)
    assert len(clusters) > 0
    # Every feature must belong to at least one cluster
    all_indices = set(idx for c in clusters for idx in c)
    assert all_indices == set(range(12))
    # No cluster should exceed max_cluster_size
    assert all(len(c) <= 5 for c in clusters)


def test_kitnet_batch_and_save_load():
    np.random.seed(42)
    # 80 normal samples of 20 features
    X_normal = (np.random.randn(80, 20) * 2.0 + 5.0).astype(np.float32)

    kitnet = KitNET(
        input_dim=20,
        max_cluster_size=6,
        hidden_ratio=0.75,
        grace_fm=20,
        grace_train=60
    )

    kitnet.fit_batch(X_normal, epochs=1)
    assert kitnet.phase == "DETECTION"
    assert kitnet.baseline_mean >= 0.0
    assert kitnet.baseline_std > 0.0

    # Normal evaluation score
    normal_score, _ = kitnet.score(X_normal[0])

    # Outlier evaluation score (simulate large exfiltration burst)
    outlier = (X_normal[0] * 50.0).astype(np.float32)
    outlier_score, feat_err = kitnet.score(outlier)

    assert outlier_score > normal_score
    assert len(feat_err) == 20

    # Test Save and Load
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        kitnet.save(tmp_path)
        loaded_kitnet = KitNET(input_dim=20)
        loaded_kitnet.load(tmp_path)

        assert loaded_kitnet.input_dim == 20
        assert len(loaded_kitnet.clusters) == len(kitnet.clusters)
        loaded_score, _ = loaded_kitnet.score(outlier)
        assert abs(loaded_score - outlier_score) < 1e-4
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
