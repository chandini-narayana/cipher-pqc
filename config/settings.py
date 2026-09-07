"""Settings — central configuration for CIPHER Phase 1.

Precedence: explicit environment variable > .env file > hard default.
No module outside config/ should read os.environ directly
(see docs/SDD.md Section 10).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from config.constants import (
    DEFAULT_CAPTURE_MODE,
    DEFAULT_CORS_ORIGIN,
    DEFAULT_DATA_DIR,
    DEFAULT_FLASK_HOST,
    DEFAULT_FLASK_PORT,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_LEVEL,
    DEFAULT_MODEL_PATH,
    DEFAULT_PCAP_PATH,
    DEFAULT_RISK_ISOLATION_THRESHOLD,
    DEFAULT_SIGNING_KEY_PATH,
)

try:
    from dotenv import load_dotenv

    _DOTENV_AVAILABLE = True
except ImportError:  # pragma: no cover - tolerate absence rather than crash
    _DOTENV_AVAILABLE = False


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of CIPHER's runtime configuration.

    Every field has a hard default (from config.constants), so
    `Settings()` with no arguments is always valid — there is no
    required configuration to provide before the app can start.
    """

    capture_mode: str = DEFAULT_CAPTURE_MODE
    pcap_path: Path = Path(DEFAULT_PCAP_PATH)
    live_interface: Optional[str] = None
    risk_isolation_threshold: int = DEFAULT_RISK_ISOLATION_THRESHOLD
    model_path: Path = Path(DEFAULT_MODEL_PATH)
    signing_key_path: Path = Path(DEFAULT_SIGNING_KEY_PATH)
    flask_host: str = DEFAULT_FLASK_HOST
    flask_port: int = DEFAULT_FLASK_PORT
    cors_origin: Optional[str] = DEFAULT_CORS_ORIGIN
    log_level: str = DEFAULT_LOG_LEVEL
    log_dir: Path = Path(DEFAULT_LOG_DIR)
    data_dir: Path = Path(DEFAULT_DATA_DIR)


def load_settings() -> Settings:
    """Build a Settings instance from environment variables, a `.env`
    file (if python-dotenv is installed and a `.env` exists), and hard
    defaults, in that order of precedence.

    This never raises: a completely empty environment produces a fully
    valid, default Settings instance.
    """
    if _DOTENV_AVAILABLE:
        # Populates os.environ from a .env file if one exists; never
        # overrides a variable that's already set in the environment.
        load_dotenv()

    return Settings(
        capture_mode=os.environ.get("CAPTURE_MODE", DEFAULT_CAPTURE_MODE),
        pcap_path=Path(os.environ.get("PCAP_PATH", DEFAULT_PCAP_PATH)),
        live_interface=os.environ.get("LIVE_INTERFACE") or None,
        risk_isolation_threshold=int(
            os.environ.get(
                "RISK_ISOLATION_THRESHOLD", DEFAULT_RISK_ISOLATION_THRESHOLD
            )
        ),
        model_path=Path(os.environ.get("MODEL_PATH", DEFAULT_MODEL_PATH)),
        signing_key_path=Path(
            os.environ.get("SIGNING_KEY_PATH", DEFAULT_SIGNING_KEY_PATH)
        ),
        flask_host=os.environ.get("FLASK_HOST", DEFAULT_FLASK_HOST),
        flask_port=int(os.environ.get("FLASK_PORT", DEFAULT_FLASK_PORT)),
        cors_origin=os.environ.get("CORS_ORIGIN") or DEFAULT_CORS_ORIGIN,
        log_level=os.environ.get("LOG_LEVEL", DEFAULT_LOG_LEVEL),
        log_dir=Path(os.environ.get("LOG_DIR", DEFAULT_LOG_DIR)),
        data_dir=Path(os.environ.get("DATA_DIR", DEFAULT_DATA_DIR)),
    )
