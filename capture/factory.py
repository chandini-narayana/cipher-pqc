"""get_capture_source(settings) -> CaptureSource

Selects OfflinePcapSource or LiveCaptureSource based on
settings.capture_mode. Not responsible for CAPTURE_MODE=mock: mock
mode bypasses capture/ and pipeline/ entirely at the dashboard layer
(see docs/SDD.md Section 6) — there is no CaptureSource for it, so
this factory raises clearly if asked for one.
"""
from __future__ import annotations

from capture.base import CaptureSource
from capture.live_source import LiveCaptureSource
from capture.offline_source import OfflinePcapSource
from config.settings import Settings
from utils.exceptions import CaptureError

_SUPPORTED_MODES = {"offline", "live"}


def get_capture_source(settings: Settings) -> CaptureSource:
    """Build the CaptureSource selected by settings.capture_mode.

    Raises:
        CaptureError: if capture_mode is "mock" (mock mode has no
            CaptureSource — see module docstring) or any other value
            outside {"offline", "live"}.
    """
    mode = settings.capture_mode.lower()

    if mode == "offline":
        return OfflinePcapSource(settings.pcap_path)
    if mode == "live":
        return LiveCaptureSource(settings.live_interface)

    if mode == "mock":
        raise CaptureError(
            "capture_mode 'mock' has no CaptureSource — mock mode is "
            "handled by dashboard/, not by capture/factory."
        )
    raise CaptureError(
        f"Unrecognized capture_mode '{settings.capture_mode}'. "
        f"Expected one of {sorted(_SUPPORTED_MODES)}."
    )