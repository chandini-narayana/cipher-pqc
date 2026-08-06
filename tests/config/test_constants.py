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
