"""Light sanity tests for config.constants — these are plain values, so
the tests just confirm the expected types and that nothing is empty."""
from config import constants


def test_app_metadata_is_populated() -> None:
    assert constants.APP_NAME
    assert constants.APP_VERSION
    assert constants.APP_PHASE


def test_risk_isolation_threshold_is_a_sane_int() -> None:
    assert isinstance(constants.DEFAULT_RISK_ISOLATION_THRESHOLD, int)
    assert 0 <= constants.DEFAULT_RISK_ISOLATION_THRESHOLD <= 10


def test_default_model_path_points_to_the_isolation_forest_artifact() -> None:
    """Step 12A: the canonical default must match what ml/train.py
    actually produces (AnomalyDetector.save() via joblib), not the
    stale, superseded risk_classifier.pkl name."""
    assert constants.DEFAULT_MODEL_PATH == "ml/artifacts/anomaly_detector.joblib"
