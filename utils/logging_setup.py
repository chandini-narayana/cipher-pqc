"""Logging configuration for CIPHER.

Configured once, from main.py, before anything else runs. Every other
module gets its own logger via logging.getLogger(__name__) and never
configures logging itself (see docs/SDD.md Section 11).
"""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config.settings import Settings


def configure_logging(settings: Settings) -> None:
    """Attach a console handler and a rotating file handler to the root
    logger, using the level and directory from `settings`.

    Safe to call more than once (existing handlers are cleared first) —
    this matters for tests that construct the app repeatedly in one
    process.
    """
    log_dir = Path(settings.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    file_handler = RotatingFileHandler(
        log_dir / "cipher.log", maxBytes=1_000_000, backupCount=3
    )
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Keep third-party libraries quiet by default (see docs/SDD.md
    # Section 11) — per-packet-level detail from our own code stays at
    # DEBUG; INFO is reserved for state transitions.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
