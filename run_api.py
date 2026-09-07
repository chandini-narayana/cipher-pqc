"""run_api.py — CIPHER Phase 12 REST API entrypoint.

A separate composition root from main.py, deliberately: main.py's
"load, run one offline capture pass, exit" contract (Step 3 onward) is
already relied on by existing tests and stays exactly as it is. This
script performs the same one-shot offline run, then — instead of
exiting — builds an ApplicationState from the results and serves them
over the REST API defined in dashboard/ until interrupted.

Sequence: load Settings -> configure logging -> build a CaptureSource
-> load the optional anomaly detector once -> load/create the signing
keypair once -> run_capture() once -> build_application_state(...) ->
dashboard.create_app(state, settings) -> app.run(...).

No orchestration logic lives here beyond this composition — the
capture/assessment/report sequence is entirely pipeline.runner's; the
REST routes and their serialization are entirely dashboard/'s.
"""
from __future__ import annotations

import logging
import sys

from capture.factory import get_capture_source
from config.settings import load_settings
from dashboard import build_application_state, create_app
from ml.loading import load_anomaly_detector
from pipeline.runner import run_capture
from signing import load_or_create_keypair
from utils.exceptions import CipherError
from utils.logging_setup import configure_logging


def main() -> int:
    """Run one offline capture pass, then serve its results over HTTP.

    Returns a process exit code only for the cases that never reach
    the server (capture_mode misconfigured/unrecognized, or "mock",
    which has no CaptureSource in Phase 1). On success this call
    blocks inside app.run() until the server is interrupted.
    """
    settings = load_settings()
    configure_logging(settings)
    logger = logging.getLogger(__name__)

    logger.info("CIPHER REST API starting up.")
    logger.info("Capture mode configured: %s", settings.capture_mode)

    if settings.capture_mode.lower() == "mock":
        # mock mode has no CaptureSource (capture/factory.py) and
        # dashboard/mock_data.py remains unimplemented in Phase 1 —
        # nothing to run, so exit gracefully rather than raising.
        logger.info("capture_mode 'mock' has no runtime pipeline in Phase 1 (no mock data source yet).")
        print("capture_mode 'mock' has no runtime pipeline in Phase 1 — exiting.")
        return 0

    try:
        capture_source = get_capture_source(settings)
        anomaly_detector = load_anomaly_detector(settings.model_path)
        public_key, secret_key = load_or_create_keypair(settings.signing_key_path)

        assessments, reports = run_capture(capture_source, anomaly_detector, public_key, secret_key)
    except CipherError:
        logger.error("Capture run failed; API will not start.", exc_info=True)
        return 1

    logger.info(
        "Capture run complete: %d device(s) assessed, %d report(s) generated. Starting API.",
        len(assessments),
        len(reports),
    )

    state = build_application_state(assessments, reports)
    app = create_app(state, settings)

    app.run(host=settings.flask_host, port=settings.flask_port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
