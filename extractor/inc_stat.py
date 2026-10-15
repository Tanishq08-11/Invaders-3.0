"""
Incremental Damped Statistics for AfterImage (Kitsune Feature Extractor)
Based on Mirsky et al., NDSS 2018.

Maintains O(1) rolling statistics over multiple exponential decay windows (lambdas)
without retaining historical packets in memory.
"""
import math
import numpy as np


class IncStat1D:
    """
    1-Dimensional Damped Incremental Statistic.
    Tracks: count/weight (w), linear sum (LS), squared sum (SS).
    Computes: weight, mean, variance, standard deviation.
    """
    def __init__(self, decay_lambda: float):
        self.decay_lambda = decay_lambda
        self.last_timestamp = None
        self.w = 0.0
        self.ls = 0.0
        self.ss = 0.0

    def update(self, val: float, timestamp: float):
        """Update statistics with a new value and timestamp."""
        if self.last_timestamp is None:
            self.last_timestamp = timestamp
            self.w = 1.0
            self.ls = float(val)
            self.ss = float(val * val)
            return

        dt = max(0.0, timestamp - self.last_timestamp)
        # Decay factor: alpha = 2^(-lambda * dt)
        decay = math.pow(2.0, -self.decay_lambda * dt)

        self.w = 1.0 + self.w * decay
        self.ls = float(val) + self.ls * decay
        self.ss = float(val * val) + self.ss * decay
        self.last_timestamp = timestamp

    @property
    def weight(self) -> float:
        return self.w

    @property
    def mean(self) -> float:
        if self.w <= 0.0:
            return 0.0
        return self.ls / self.w

    @property
    def variance(self) -> float:
        if self.w <= 0.0:
            return 0.0
        var = (self.ss / self.w) - (self.mean ** 2)
        return max(0.0, var)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


class IncStat2D:
    """
    2-Dimensional Damped Incremental Statistic.
    Tracks covariance and Pearson correlation between two variables X and Y.
    """
    def __init__(self, decay_lambda: float):
        self.decay_lambda = decay_lambda
        self.stat_x = IncStat1D(decay_lambda)
        self.stat_y = IncStat1D(decay_lambda)
        self.last_timestamp = None
        self.rs = 0.0  # Residual sum

    def update(self, val_x: float, val_y: float, timestamp: float):
        mean_x_prior = self.stat_x.mean
        mean_y_prior = self.stat_y.mean

        if self.last_timestamp is None:
            self.last_timestamp = timestamp
            self.rs = 0.0
        else:
            dt = max(0.0, timestamp - self.last_timestamp)
            decay = math.pow(2.0, -self.decay_lambda * dt)
            self.rs = self.rs * decay + (val_x - mean_x_prior) * (val_y - mean_y_prior)
            self.last_timestamp = timestamp

        self.stat_x.update(val_x, timestamp)
        self.stat_y.update(val_y, timestamp)

    @property
    def covariance(self) -> float:
        w = self.stat_x.weight
        if w <= 0.0:
            return 0.0
        return self.rs / w

    @property
    def correlation(self) -> float:
        std_x = self.stat_x.std
        std_y = self.stat_y.std
        denom = std_x * std_y
        if denom < 1e-7:
            return 0.0
        cov = self.covariance
        corr = cov / denom
        return float(np.clip(corr, -1.0, 1.0))
