"""Thresholds, default paths, and app metadata shared across CIPHER.

These are plain constants — no logic, no I/O — so every other module
(including config/settings.py itself) can import them without creating
any import-order problems.
"""

APP_NAME = "CIPHER"
APP_TAGLINE = (
    "Cryptographic Intelligence for Post-quantum Hazard Evaluation "
    "and Readiness Assessment"
)
APP_VERSION = "0.1.0-dev"
APP_PHASE = "Phase 1 (Windows, hardware-free)"

DEFAULT_CAPTURE_MODE = "offline"
DEFAULT_PCAP_PATH = "tests/fixtures/sample.pcap"

# Defined now, even though nothing in Phase 1 acts on it yet, so Phase 2
# doesn't invent a second source of truth for this threshold
# (see docs/SDD.md Section 15).
DEFAULT_RISK_ISOLATION_THRESHOLD = 7

DEFAULT_MODEL_PATH = "ml/artifacts/anomaly_detector.joblib"
DEFAULT_SIGNING_KEY_PATH = "data/keys/"
DEFAULT_FLASK_HOST = "127.0.0.1"
DEFAULT_FLASK_PORT = 5000

# No default: the frontend's dev-server origin is unknown to the backend
# ahead of time. None means "no cross-origin allowance" — never a wildcard
# (see docs/SDD.md's Phase 12 addendum).
DEFAULT_CORS_ORIGIN = None
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_DIR = "logs/"
DEFAULT_DATA_DIR = "data/"
