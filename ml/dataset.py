"""Synthetic feature-matrix generator for testing and demonstrating
AnomalyDetector.

IMPORTANT — research integrity: this generates SYNTHETIC data only. It
is not derived from, and makes no claim to represent, real hospital,
campus, enterprise, or IoT network traffic. It exists solely to give
software tests and ml/train.py's demonstration script deterministic,
reproducible input. Any evaluation of Isolation Forest's real-world
effectiveness requires real, labeled traffic data that does not yet
exist in this project — see docs/SDD.md Section 21.
"""
from __future__ import annotations

import numpy as np

from ml.features import NUM_FEATURES


def generate_synthetic_feature_matrix(
    n_normal: int = 180,
    n_outliers: int = 10,
    random_state: int = 42,
) -> np.ndarray:
    """Build a synthetic, deterministic (seeded) feature matrix shaped
    like ml.features.vectorize_features() output: `n_normal` rows
    resembling well-configured HTTPS traffic (high entropy, modern TLS,
    strong keys, PFS present), and `n_outliers` rows resembling clearly
    weak/legacy traffic (low entropy, TLS 1.0, weak keys, no PFS,
    plaintext HTTP) — for exercising AnomalyDetector against a small,
    known-shape dataset in tests and the training demo script only.

    Column order matches ml.features.FEATURE_NAMES exactly.
    """
    rng = np.random.default_rng(random_state)

    normal = np.column_stack(
        [
            rng.uniform(7.0, 8.0, n_normal),
            rng.uniform(200, 1500, n_normal),
            rng.choice([1.2, 1.3], n_normal),
            np.ones(n_normal),
            rng.choice([2048, 3072, 4096], n_normal).astype(float),
            np.ones(n_normal),
            rng.choice([0.0, 1.0], n_normal, p=[0.2, 0.8]),
            np.ones(n_normal), np.zeros(n_normal), np.zeros(n_normal),
            np.zeros(n_normal), np.zeros(n_normal),
        ]
    )

    outliers = np.column_stack(
        [
            rng.uniform(1.0, 3.0, n_outliers),
            rng.uniform(10, 60, n_outliers),
            np.full(n_outliers, 1.0),
            np.ones(n_outliers),
            rng.choice([512, 768], n_outliers).astype(float),
            np.ones(n_outliers),
            np.zeros(n_outliers),
            np.zeros(n_outliers), np.ones(n_outliers), np.zeros(n_outliers),
            np.zeros(n_outliers), np.zeros(n_outliers),
        ]
    )

    matrix = np.vstack([normal, outliers])
    assert matrix.shape[1] == NUM_FEATURES
    return matrix