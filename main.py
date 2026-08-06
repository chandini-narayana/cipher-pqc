"""main.py — CIPHER Phase 1 composition root.

At full implementation, this constructs a capture source, RiskEngine,
MLClassifier, DilithiumSigner, ReportGenerator, and DeviceRegistry, then
hands them to pipeline.runner.Pipeline and dashboard.app.create_app. It
contains no orchestration logic itself (see docs/SDD.md D3) — that lives
in pipeline/.

CURRENT STATE (Step 3 — Configuration module):
Configuration and logging are real and load_settings()/configure_logging()
are actually wired in. capture/, risk/, ml/, signing/, reports/, pipeline/,
and dashboard/ are not implemented yet, so there is nothing yet to run a
detection pipeline against. Rather than fake a working capture pipeline
or crash, this prints a startup banner from real configuration and exits
gracefully (exit code 0) once it has confirmed there is no implemented
capture source to run — exactly the behavior specified for this step.
"""
from __future__ import annotations

import logging
import sys

from config.settings import load_settings
from utils.logging_setup import configure_logging
from config.constants import APP_NAME, APP_PHASE, APP_TAGLINE, APP_VERSION


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
    """Load configuration, configure logging, print the startup banner,
    and exit gracefully since no capture source is implemented yet.

    Returns the process exit code (0 = clean exit, including the
    "nothing to run yet" case — this is expected Phase 1 behavior at
    this step, not a failure).
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

    # capture/, pipeline/, and dashboard/ are not implemented yet (see
    # docs/SDD.md for the build order). Rather than raise or simulate a
    # working pipeline, we detect that state explicitly and exit
    # gracefully so `python main.py` is always a clean, honest run.
    logger.warning(
        "No capture source is implemented yet (capture/ and pipeline/ "
        "arrive in later steps). Exiting gracefully."
    )
    print(
        "No capture source implemented yet — exiting gracefully.\n"
        "See docs/SDD.md for the build plan."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
