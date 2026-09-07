"""load_anomaly_detector — runtime loading for a previously trained
AnomalyDetector artifact.

Approved fail-open-for-ML policy (docs/SDD.md Step 12A addendum): QRS
(risk/) remains the primary, always-on risk engine; Isolation Forest is
a secondary, optional signal. A MISSING model artifact is not a
startup failure — CIPHER runs QRS-only in that case, and Step 10
fusion already defines anomaly_assessment=None -> the QRS category
passes through unchanged (fusion/risk_fusion.py). A configured
artifact that IS present but corrupt or otherwise fails to load is a
different, genuine failure and is never silently treated the same as
"absent" — see load_anomaly_detector's Raises section.

This module only loads an already-trained model. It never fits,
trains, generates synthetic data (ml/dataset.py), or saves anything —
those remain ml/train.py's job, run explicitly and separately from
ordinary runtime.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Union

from ml.classifier import AnomalyDetector

logger = logging.getLogger(__name__)


def load_anomaly_detector(model_path: Union[str, Path]) -> Optional[AnomalyDetector]:
    """Load a previously trained AnomalyDetector from `model_path`.

    Args:
        model_path: path to a joblib artifact previously produced by
            AnomalyDetector.save() (see ml/train.py).

    Returns:
        The loaded AnomalyDetector if `model_path` exists, else None
        (after logging one WARNING) — meaning ML is simply unavailable
        for this run; QRS-based risk assessment is unaffected.

    Raises:
        Whatever AnomalyDetector.load(model_path) raises when the path
        exists but cannot be loaded as a valid AnomalyDetector — e.g.
        TypeError (the file contains some other object) or any
        joblib/pickle deserialization error for a corrupt file. These
        propagate unmodified: a broken configured artifact is a
        genuine configuration problem, not the same as no artifact,
        and must not be silently downgraded to None.
    """
    path = Path(model_path)

    if not path.exists():
        logger.warning(
            "Anomaly detection model not found at %s — continuing without ML; "
            "QRS risk assessment is unaffected.",
            path,
        )
        return None

    return AnomalyDetector.load(path)
