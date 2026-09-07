"""main.py — CIPHER Phase 1 composition root.

Loads configuration, configures logging, builds a CaptureSource, loads
the optional anomaly detector and the signing keypair once each, hands
them to pipeline.runner.run_capture for one synchronous offline pass,
and logs a concise completion summary. No orchestration logic lives
here (see docs/SDD.md D3) — that lives in pipeline/.

CURRENT STATE (Phase 11 — Backend Runtime Orchestration):
capture/, entropy/, fingerprint/, risk/, ml/, fusion/, signing/, and
reports/ are all implemented; pipeline.runner.run_capture wires them
into one offline run. REST, the dashboard, and live capture remain
unimplemented — CAPTURE_MODE=mock and CAPTURE_MODE=live both fail
clearly and explicitly rather than silently doing nothing (see
docs/SDD.md's Phase 11 addendum).
"""
from __future__ import annotations

import logging
import sys

from capture.factory import get_capture_source
from config.constants import APP_NAME, APP_PHASE, APP_TAGLINE, APP_VERSION
from config.settings import load_settings
from ml.loading import load_anomaly_detector
from pipeline.runner import run_capture
from signing import load_or_create_keypair
from utils.exceptions import CipherError
from utils.logging_setup import configure_logging


def _render_banner(settings) -> str:
    """Build the startup banner text from live configuration, not
    hard-coded values, so it always reflects what actually loaded."""
    return (
        "\n"
        "==============================================\n"
        f"  {APP_NAME} — {APP_TAGLINE}\n"
        f"  {APP_PHASE} — v{APP_VERSION}\n"
        "==============================================\n"
        f"  Capture mode : {settings.capture_mode}\n"
        f"  Log level    : {settings.log_level}\n"
        f"  Log directory: {settings.log_dir}\n"
        f"  Data directory: {settings.data_dir}\n"
        "==============================================\n"
    )


def main() -> int:
    """Load configuration, configure logging, and run one synchronous
    offline capture pass to completion.

    Returns the process exit code: 0 for a successful offline
    completion (including CAPTURE_MODE=mock, which has no runtime
    pipeline in Phase 1 and exits gracefully rather than attempting
    one), non-zero if capture_mode is misconfigured or unrecognized.
    """
    settings = load_settings()
    configure_logging(settings)
    logger = logging.getLogger(__name__)

    print(_render_banner(settings))
    logger.info("%s starting up.", APP_NAME)
    logger.info("Capture mode configured: %s", settings.capture_mode)
    logger.info(
        "Logging initialized at %s, writing to %s", settings.log_level, settings.log_dir
    )

    if settings.capture_mode.lower() == "mock":
        # mock mode has no CaptureSource (capture/factory.py) and is
        # meant to be served by dashboard/, which doesn't exist in
        # Phase 1 — nothing to run, so exit gracefully rather than
        # raising the CaptureError get_capture_source would give it.
        logger.info("capture_mode 'mock' has no runtime pipeline in Phase 1 (no dashboard yet).")
        print("capture_mode 'mock' has no runtime pipeline in Phase 1 — exiting gracefully.")
        return 0

    try:
        capture_source = get_capture_source(settings)
        anomaly_detector = load_anomaly_detector(settings.model_path)
        public_key, secret_key = load_or_create_keypair(settings.signing_key_path)

        assessments, reports = run_capture(
            capture_source, anomaly_detector, public_key, secret_key
        )
    except CipherError:
        logger.error("Capture run failed.", exc_info=True)
        return 1

    logger.info(
        "Capture run complete: %d device(s) assessed, %d report(s) generated.",
        len(assessments),
        len(reports),
    )
    print(
        f"Capture run complete: {len(assessments)} device(s) assessed, "
        f"{len(reports)} report(s) generated."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
