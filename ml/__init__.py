"""ml — Isolation Forest anomaly detection.

Isolation Forest performs anomaly detection only and never replaces
risk/'s rule-based Quantum Risk Score — the two are independent
signals, to be combined in a later, unimplemented Risk Fusion
milestone. This package has no dependency on capture/, entropy/,
fingerprint/, risk/, packet parsing, network I/O, REST, the frontend,
PDF generation, signing, or Raspberry Pi.

See docs/SDD.md Section 21 for the feature schema, contamination and
random_state choices, and anomaly-score/confidence semantics.
"""

from ml.classifier import DEFAULT_CONTAMINATION, DEFAULT_RANDOM_STATE, AnomalyDetector
from ml.dataset import generate_synthetic_feature_matrix
from ml.features import FEATURE_NAMES, NUM_FEATURES, vectorize_features

__all__ = [
    "AnomalyDetector",
    "DEFAULT_CONTAMINATION",
    "DEFAULT_RANDOM_STATE",
    "vectorize_features",
    "FEATURE_NAMES",
    "NUM_FEATURES",
    "generate_synthetic_feature_matrix",
]