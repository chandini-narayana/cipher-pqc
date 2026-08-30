"""CLI entry point: fit an AnomalyDetector on synthetic data and save it.

    python -m ml.train

This is a small, minimal demonstration of the fit -> save workflow,
not a production training pipeline. It uses ONLY the synthetic data
generator in ml/dataset.py — see that module's docstring for why real
training data does not exist yet in this project. Running this script
does not produce a model validated against real traffic; it exists to
exercise and demonstrate the persistence path end to end.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ml.classifier import AnomalyDetector
from ml.dataset import generate_synthetic_feature_matrix

logger = logging.getLogger(__name__)

DEFAULT_OUTPUT_PATH = Path(__file__).resolve().parent / "artifacts" / "anomaly_detector.joblib"


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    logger.info(
        "Generating SYNTHETIC training data (not real traffic — see "
        "ml/dataset.py docstring)."
    )
    feature_matrix = generate_synthetic_feature_matrix()
    logger.info("Synthetic feature matrix shape: %s", feature_matrix.shape)

    detector = AnomalyDetector()
    detector.fit(feature_matrix)
    logger.info(
        "Fitted AnomalyDetector (contamination=%s, random_state=%s).",
        detector._contamination, detector._random_state,
    )

    DEFAULT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    detector.save(DEFAULT_OUTPUT_PATH)
    logger.info("Saved to %s", DEFAULT_OUTPUT_PATH)


if __name__ == "__main__":
    main()