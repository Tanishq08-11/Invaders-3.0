"""
Unit Tests for AfterImage Feature Extractor & Incremental Statistics
"""
import pytest
import numpy as np
from extractor.inc_stat import IncStat1D, IncStat2D
from extractor.afterimage import AfterImage


def test_inc_stat_1d():
    stat = IncStat1D(decay_lambda=1.0)
    t0 = 1000.0

    stat.update(100.0, t0)
    assert stat.weight == 1.0
    assert stat.mean == 100.0
    assert stat.std == 0.0

    # Add second sample after small dt
    stat.update(200.0, t0 + 0.1)
    assert stat.weight > 1.0
    assert 100.0 < stat.mean < 200.0
    assert stat.std > 0.0


def test_inc_stat_2d():
    stat = IncStat2D(decay_lambda=1.0)
    t0 = 1000.0

    stat.update(10.0, 100.0, t0)
    stat.update(20.0, 200.0, t0 + 0.1)
    stat.update(30.0, 300.0, t0 + 0.2)

    assert -1.0 <= stat.correlation <= 1.0
    # Positive correlation between X and Y
    assert stat.correlation > 0.8


def test_afterimage_extraction():
    extractor = AfterImage(lambdas=[5.0, 3.0, 1.0, 0.1, 0.01])
    names = extractor.get_feature_names()
    assert len(names) == 100
    assert extractor.get_feature_dimension() == 100

    # Extract single packet
    vec = extractor.update_and_extract(
        timestamp=1600000000.0,
        src_ip="192.168.1.50",
        dst_ip="203.0.113.10",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        length=1460.0
    )

    assert isinstance(vec, np.ndarray)
    assert vec.shape == (100,)
    assert not np.isnan(vec).any()
    assert not np.isinf(vec).any()
