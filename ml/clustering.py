"""
Feature Mapper for KitNET.
Partitions the high-dimensional feature space into small, correlated clusters
using Hierarchical Agglomerative Clustering (HAC) on normal baseline traffic.
Based on Mirsky et al., NDSS 2018.
"""
from typing import List
import numpy as np
from scipy.spatial.distance import squareform
from scipy.cluster.hierarchy import linkage, fcluster


class FeatureMapper:
    """
    Groups correlated network features into distinct clusters.
    Ensures each cluster has size <= max_cluster_size so that individual
    ensemble autoencoders remain compact, fast, and sensitive to local anomalies.
    """
    def __init__(self, max_cluster_size: int = 10):
        self.max_cluster_size = max_cluster_size
        self.clusters: List[List[int]] = []

    def fit(self, X: np.ndarray) -> List[List[int]]:
        """
        Fits feature clusters using correlation distance on normal baseline data.
        X: shape (N, D)
        Returns: list of feature index clusters, e.g. [[0, 3, 7], [1, 2], ...]
        """
        N, D = X.shape
        if D <= self.max_cluster_size:
            self.clusters = [list(range(D))]
            return self.clusters

        # Add small jitter to avoid divide-by-zero on invariant features
        std = np.std(X, axis=0)
        active_indices = np.where(std > 1e-6)[0]
        inactive_indices = np.where(std <= 1e-6)[0]

        if len(active_indices) < 2:
            # Fallback to chunking
            self.clusters = [
                list(range(i, min(i + self.max_cluster_size, D)))
                for i in range(0, D, self.max_cluster_size)
            ]
            return self.clusters

        # Compute Pearson correlation matrix on active features
        X_active = X[:, active_indices]
        corr = np.corrcoef(X_active, rowvar=False)
        corr = np.nan_to_num(corr, nan=0.0)

        # Distance matrix: 1 - |r|
        dist = 1.0 - np.abs(corr)
        np.fill_diagonal(dist, 0.0)
        dist = np.clip(dist, 0.0, 2.0)

        # Convert to condensed distance matrix for linkage
        condensed_dist = squareform(dist, checks=False)
        Z = linkage(condensed_dist, method='complete')

        # Find threshold that respects max_cluster_size
        # We start with a conservative cut and refine
        best_clusters = None
        for t in np.linspace(0.1, 1.5, 30):
            labels = fcluster(Z, t=t, criterion='distance')
            cluster_map = {}
            for idx, label in enumerate(labels):
                orig_feat_idx = active_indices[idx]
                cluster_map.setdefault(label, []).append(orig_feat_idx)

            max_size = max(len(c) for c in cluster_map.values())
            if max_size <= self.max_cluster_size:
                best_clusters = list(cluster_map.values())
                break

        if best_clusters is None:
            # Fallback: split any oversized clusters
            cluster_map = {}
            labels = fcluster(Z, t=0.5, criterion='distance')
            for idx, label in enumerate(labels):
                orig_feat_idx = active_indices[idx]
                cluster_map.setdefault(label, []).append(orig_feat_idx)

            best_clusters = []
            for c in cluster_map.values():
                for i in range(0, len(c), self.max_cluster_size):
                    best_clusters.append(c[i:i + self.max_cluster_size])

        # Distribute inactive/constant features across existing clusters
        if len(inactive_indices) > 0:
            c_idx = 0
            for feat_idx in inactive_indices:
                if len(best_clusters[c_idx]) < self.max_cluster_size:
                    best_clusters[c_idx].append(int(feat_idx))
                else:
                    best_clusters.append([int(feat_idx)])
                c_idx = (c_idx + 1) % len(best_clusters)

        self.clusters = best_clusters
        return self.clusters
