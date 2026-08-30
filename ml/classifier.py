"""AnomalyDetector — wraps sklearn.ensemble.IsolationForest for
CIPHER's anomaly-detection stage.

File kept at ml/classifier.py per the existing scaffold (Step 2), but
the class is deliberately NOT named MLClassifier: that name implied a
LOW/MEDIUM/HIGH category classifier (the original Decision Tree plan).
Isolation Forest doesn't classify a risk category at all — it flags
outliers and scores how unusual they look. AnomalyDetector names that
accurately. See docs/SDD.md Section 21.

A class is used here (unlike entropy/, fingerprint/, risk/, which are
all plain functions) because Isolation Forest is genuinely stateful:
a fitted model holds learned structure that must persist across
fit() and later predict_one() calls, and must be saved/loaded as a
unit. There is real state to hold, unlike the earlier pure-function
modules.

Independent of packet capture, Scapy, TLS parsing, entropy
calculation, protocol fingerprinting, REST APIs, the frontend, PDF
generation, signing, and Raspberry Pi — this module only consumes
already-vectorized numeric features (see ml/features.py) and produces
an AnomalyAssessment. It is also independent of risk/: no Quantum Risk
Score or its components are read here, and this module's output is
never combined with risk/'s output — that fusion is an explicitly
later, unimplemented milestone.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Union

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ml.features import NUM_FEATURES, vectorize_features
from models.anomaly_assessment import AnomalyAssessment
from models.device_features import DeviceFeatures

_MIN_TRAINING_SAMPLES = 10

DEFAULT_CONTAMINATION = 0.05

DEFAULT_RANDOM_STATE = 42


class AnomalyDetector:
    """A fitted-or-not-yet-fitted Isolation Forest, scoped to
    CIPHER's fixed feature schema (ml.features.FEATURE_NAMES).

    Anomaly score semantics (read this before using anomaly_score):
    sklearn's IsolationForest.decision_function() returns HIGHER
    values for NORMAL points and LOWER (more negative) values for
    ANOMALOUS points — the opposite of what "anomaly score" should
    intuitively mean. This class negates it, so
    AnomalyAssessment.anomaly_score is HIGH when a point looks MORE
    anomalous and LOW (or negative) when it looks normal — matching
    the field's own name and avoiding a very likely source of
    downstream bugs if left in sklearn's native convention.

    AnomalyAssessment.confidence is NOT a calibrated probability —
    IsolationForest is not a probabilistic estimator and provides no
    native likelihood output. confidence is a sigmoid transform of
    anomaly_score, scaled by the standard deviation of decision_function
    scores observed across the training set (computed once, in fit(),
    and reused at every predict_one() call). This scaling is adaptive
    (it reflects whatever score spread THIS fitted model actually
    produces) rather than a fixed magic constant tuned to one dataset.
    Treat confidence as "how far this observation's anomaly score sits
    from what training considered typical," not as "P(this is
    anomalous)" in any statistically calibrated sense.
    """

    def __init__(
        self,
        contamination: Union[float, str] = DEFAULT_CONTAMINATION,
        random_state: int = DEFAULT_RANDOM_STATE,
    ) -> None:
        self._contamination = contamination
        self._random_state = random_state
        self._model = IsolationForest(
            contamination=contamination, random_state=random_state
        )
        self._fitted = False
        self._score_std: float = 1.0

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def fit(self, feature_matrix: np.ndarray) -> None:
        """Fit the Isolation Forest on `feature_matrix` — one row per
        DeviceFeatures observation, columns matching
        ml.features.FEATURE_NAMES exactly.

        Raises:
            ValueError: if `feature_matrix` isn't 2-D with exactly
                NUM_FEATURES columns, or has fewer than
                _MIN_TRAINING_SAMPLES rows.
        """
        if feature_matrix.ndim != 2 or feature_matrix.shape[1] != NUM_FEATURES:
            raise ValueError(
                f"feature_matrix must be 2-D with {NUM_FEATURES} columns "
                f"(matching ml.features.FEATURE_NAMES), got shape {feature_matrix.shape}"
            )
        if feature_matrix.shape[0] < _MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"feature_matrix has {feature_matrix.shape[0]} rows; at least "
                f"{_MIN_TRAINING_SAMPLES} are required for a meaningful fit"
            )

        self._model.fit(feature_matrix)

        training_scores = self._model.decision_function(feature_matrix)
        self._score_std = max(float(training_scores.std()), 1e-6)

        self._fitted = True

    def predict_one(self, features: DeviceFeatures) -> AnomalyAssessment:
        """Score a single DeviceFeatures observation against the
        already-fitted model.

        Raises:
            RuntimeError: if called before fit() or load().
        """
        if not self._fitted:
            raise RuntimeError(
                "AnomalyDetector.predict_one() called before fit() or load() "
                "— there is no fitted model to score against."
            )

        vector = vectorize_features(features).reshape(1, -1)

        raw_decision = float(self._model.decision_function(vector)[0])
        anomaly_score = -raw_decision

        is_anomaly = bool(self._model.predict(vector)[0] == -1)

        confidence = 1.0 / (1.0 + math.exp(-anomaly_score / self._score_std))
        confidence = min(max(confidence, 0.0), 1.0)

        return AnomalyAssessment(
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            confidence=confidence,
        )

    def save(self, path: Union[str, Path]) -> None:
        """Persist this detector to `path` via joblib. Minimal, local
        persistence only — no registry, no versioning, no remote
        storage (see docs/SDD.md Section 21).

        Raises:
            RuntimeError: if called before fit().
        """
        if not self._fitted:
            raise RuntimeError("cannot save an AnomalyDetector that has not been fit()")
        joblib.dump(self, str(path))

    @classmethod
    def load(cls, path: Union[str, Path]) -> "AnomalyDetector":
        """Load a previously saved AnomalyDetector from `path`.

        Raises:
            TypeError: if the loaded object isn't an AnomalyDetector.
        """
        obj = joblib.load(str(path))
        if not isinstance(obj, cls):
            raise TypeError(
                f"{path} does not contain an AnomalyDetector (got {type(obj).__name__})"
            )
        return obj