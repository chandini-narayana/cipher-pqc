"""run_demo.py — CIPHER Phase 15 self-contained integrated application.

A third composition root, alongside main.py (offline, run-and-exit)
and run_api.py (API-only dev server) — neither is modified or
replaced by this script. Performs the identical one-shot offline
composition run_api.py does, then serves BOTH the compiled React
production UI (this repo's own committed web/ directory) and the
existing /api/* REST contract from a single Flask process on one
origin (see docs/SDD.md's Phase 15 addendum).

No cipher-frontend checkout, Node, npm, or Vite is required at
runtime: web/ is a pre-built, static release artifact shipped inside
this repository, resolved relative to this file's own location (not
the caller's cwd), so `python run_demo.py` works from a normal
checkout regardless of the working directory it's launched from.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from capture.factory import get_capture_source
from config.settings import load_settings
from dashboard import build_application_state, create_app
from dashboard.spa import MissingWebBuildError, register_spa, validate_web_build
from enforcement import NoOpIsolationBackend
from ml.loading import load_anomaly_detector
from pipeline.runner import run_capture
from signing import load_or_create_keypair
from utils.exceptions import CipherError
from utils.logging_setup import configure_logging

WEB_DIR = Path(__file__).resolve().parent / "web"


def main() -> int:
    """Validate the bundled web build, run one offline capture pass,
    then serve the integrated application (React UI + REST API) over
    HTTP until interrupted.

    Returns a process exit code only for the cases that never reach
    the server (missing/incomplete web/ build, capture_mode
    misconfigured/unrecognized, or "mock", which has no CaptureSource
    in Phase 1). On success this call blocks inside app.run() until
    the server is interrupted.
    """
    settings = load_settings()
    configure_logging(settings)
    logger = logging.getLogger(__name__)

    logger.info("CIPHER integrated demo application starting up.")
    logger.info("Capture mode configured: %s", settings.capture_mode)

    # Checked first, before any capture work: a missing/incomplete web
    # build must fail startup immediately, not after spending time on
    # capture and key generation (see docs/SDD.md's Phase 15 addendum).
    try:
        validate_web_build(WEB_DIR)
    except MissingWebBuildError as exc:
        logger.error("Web application build missing or incomplete.")
        print(str(exc))
        return 1

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
        # Windows, hardware-free Phase 1: isolation decisions are made
        # and logged, never physically enforced (see docs/SDD.md's
        # Phase 14 addendum). Swapped at the composition root only.
        isolation_backend = NoOpIsolationBackend()

        assessments, reports = run_capture(
            capture_source,
            anomaly_detector,
            public_key,
            secret_key,
            isolation_backend,
            risk_isolation_threshold=settings.risk_isolation_threshold,
        )
    except CipherError:
        logger.error("Capture run failed; integrated application will not start.", exc_info=True)
        return 1

    logger.info(
        "Capture run complete: %d device(s) assessed, %d report(s) generated. Starting integrated app.",
        len(assessments),
        len(reports),
    )

    state = build_application_state(assessments, reports)
    app = create_app(state, settings)
    register_spa(app, WEB_DIR)

    print(f"CIPHER is running at http://{settings.flask_host}:{settings.flask_port}")
    app.run(host=settings.flask_host, port=settings.flask_port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
