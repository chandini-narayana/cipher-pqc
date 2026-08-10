"""main.py — CIPHER Phase 1 composition root.

At full implementation, this constructs a capture source, RiskEngine,
MLClassifier, DilithiumSigner, ReportGenerator, and DeviceRegistry, then
hands them to pipeline.runner.Pipeline and dashboard.app.create_app. It
contains no orchestration logic itself (see docs/SDD.md D3) — that lives
in pipeline/.

CURRENT STATE (Step 5 — Packet Parsing / capture):
Configuration and logging are real (Step 3). capture/ is now fully
implemented for offline .pcap replay, with live capture as a
documented scaffold (Step 5). risk/, ml/, signing/, reports/, and
dashboard/ are not implemented yet, and — per D3 — orchestrating a
capture source into a running pipeline is pipeline/'s job, not
main.py's; pipeline/ does not exist yet either. Rather than have this
composition root reach into capture/ directly and start improvising
orchestration logic (which D3 exists specifically to prevent), main.py
still prints a startup banner from real configuration and exits
gracefully (exit code 0), now correctly noting that a capture source
exists but nothing yet drives it.
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
    and exit gracefully since no pipeline exists yet to drive capture.

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

    # capture/ is implemented (Step 5), but pipeline/ — the only thing
    # allowed to actually drive a capture source through the detection
    # sequence, per D3 — is not built yet. Rather than have this
    # composition root improvise orchestration, we detect that state
    # explicitly and exit gracefully so `python main.py` stays a clean,
    # honest run.
    logger.warning(
        "Capture source is implemented, but no pipeline exists yet to "
        "run it (pipeline/ arrives in a later step). Exiting gracefully."
    )
    print(
        "Capture is implemented, but no pipeline exists yet to run it "
        "— exiting gracefully.\nSee docs/SDD.md for the build plan."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())