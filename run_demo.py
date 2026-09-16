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

Default demo data (see docs/SDD.md's Phase 15 evaluation addendum):
unless PCAP_PATH is explicitly set, this script — and only this
script — defaults to tests/fixtures/demo_presentation.pcap instead of
config.constants.DEFAULT_PCAP_PATH's sample.pcap, so the live
dashboard shows a genuine LOW/MEDIUM/HIGH spread and a real isolation-
decision log line. config/constants.py and main.py/run_api.py's own
default are untouched — this is a run_demo.py-only override, applied
via dataclasses.replace() on the already-loaded Settings, never an
env-var mutation (which would leak across an in-process caller, e.g.
a test importing and calling main() directly).

demo_presentation.pcap is a COMMITTED runtime asset (an explicit
`!tests/fixtures/demo_presentation.pcap` exception to the otherwise
gitignored tests/fixtures/*.pcap pattern), not something this script
generates: runtime fixture generation is deliberately kept separate
from test fixture generation (tests/conftest.py's own auto-generation
is a test-suite-only safety net this module never imports or depends
on). If the committed file is ever missing, this fails clearly and
immediately — the same fail-fast pattern already used for a missing
web/ build — rather than spending ~50-60s regenerating it at startup,
which would defeat the <30s boot target.
"""
from __future__ import annotations

import logging
import os
import sys
from dataclasses import replace
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
# A plain literal path, deliberately NOT imported from
# tests.fixtures.generate_evaluation_fixtures: this module must never
# pull in that generator (scapy/cryptography fixture-construction
# code) or be able to invoke it at runtime — see module docstring.
DEFAULT_DEMO_PCAP_PATH = Path(__file__).resolve().parent / "tests" / "fixtures" / "demo_presentation.pcap"


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

    if "PCAP_PATH" not in os.environ:
        if not DEFAULT_DEMO_PCAP_PATH.exists():
            message = (
                "CIPHER presentation data is missing.\n"
                f"Expected: {DEFAULT_DEMO_PCAP_PATH}\n"
                "This file is a committed runtime asset, not something "
                "generated at startup. Restore it from version control "
                "(e.g. `git checkout -- tests/fixtures/demo_presentation.pcap`), "
                "or run `python -m tests.fixtures.generate_evaluation_fixtures` "
                "to rebuild it deterministically, then try again."
            )
            logger.error("Presentation pcap missing: %s", DEFAULT_DEMO_PCAP_PATH)
            print(message)
            return 1
        settings = replace(settings, pcap_path=DEFAULT_DEMO_PCAP_PATH)
    logger.info("Using pcap: %s", settings.pcap_path)

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
    # Explicit, not relying on Flask's own default-from-app.debug behavior:
    # the presentation demo must never run Werkzeug's reloader, which
    # spawns and manages a second worker subprocess of its own — a
    # completely different, unrelated mechanism from the Windows venv-
    # launcher behavior documented in launch_cipher.py (see its module
    # docstring). debug was already False by default here (confirmed via
    # the "Debug mode: off" banner Flask always printed); this just makes
    # that guarantee explicit rather than implicit.
    app.run(host=settings.flask_host, port=settings.flask_port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
