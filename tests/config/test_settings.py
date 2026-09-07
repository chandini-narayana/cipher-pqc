"""Unit tests for config.settings.

Covers: default values with no environment set, environment-variable
overrides, and precedence (env var beats default). A .env-file test is
intentionally omitted here — that path is exercised by the presence/
absence of python-dotenv, not by unit-testable business logic — and is
covered instead by a smoke check that load_settings() never raises.
"""
import os
from pathlib import Path

import pytest

from config.constants import (
    DEFAULT_CAPTURE_MODE,
    DEFAULT_FLASK_PORT,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MODEL_PATH,
    DEFAULT_RISK_ISOLATION_THRESHOLD,
)
from config.settings import Settings, load_settings


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure no relevant env var leaks in from the host environment,
    so tests are deterministic regardless of where they run."""
    for key in (
        "CAPTURE_MODE",
        "PCAP_PATH",
        "LIVE_INTERFACE",
        "RISK_ISOLATION_THRESHOLD",
        "MODEL_PATH",
        "SIGNING_KEY_PATH",
        "FLASK_HOST",
        "FLASK_PORT",
        "LOG_LEVEL",
        "LOG_DIR",
        "DATA_DIR",
    ):
        monkeypatch.delenv(key, raising=False)


def test_settings_has_valid_defaults_with_no_args() -> None:
    """Settings() with zero arguments must always be valid — there is
    no required configuration to provide before the app can start."""
    settings = Settings()
    assert settings.capture_mode == DEFAULT_CAPTURE_MODE
    assert settings.risk_isolation_threshold == DEFAULT_RISK_ISOLATION_THRESHOLD
    assert settings.flask_port == DEFAULT_FLASK_PORT


def test_load_settings_uses_defaults_when_env_is_empty() -> None:
    settings = load_settings()
    assert settings.capture_mode == DEFAULT_CAPTURE_MODE
    assert settings.log_level == DEFAULT_LOG_LEVEL


def test_load_settings_respects_env_var_override(monkeypatch) -> None:
    monkeypatch.setenv("CAPTURE_MODE", "mock")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("FLASK_PORT", "9000")

    settings = load_settings()

    assert settings.capture_mode == "mock"
    assert settings.log_level == "DEBUG"
    assert settings.flask_port == 9000


def test_settings_model_path_defaults_to_the_isolation_forest_artifact() -> None:
    settings = Settings()
    assert settings.model_path == Path(DEFAULT_MODEL_PATH)
    assert settings.model_path == Path("ml/artifacts/anomaly_detector.joblib")


def test_load_settings_respects_model_path_env_override(monkeypatch) -> None:
    monkeypatch.setenv("MODEL_PATH", "custom/models/detector.joblib")

    settings = load_settings()

    assert settings.model_path == Path("custom/models/detector.joblib")


def test_load_settings_never_raises_on_empty_environment() -> None:
    """A completely empty environment must still produce a valid
    Settings instance — configuration is never a hard requirement."""
    settings = load_settings()
    assert isinstance(settings, Settings)
