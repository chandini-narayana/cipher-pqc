"""Unit tests for capture.live_source.LiveCaptureSource.

Per docs/SDD.md Section 13: LiveCaptureSource gets exactly one test —
confirming it satisfies the CaptureSource interface and that calling
read_packets() raises LiveCaptureNotImplementedError immediately. This
IS what "documented scaffold" means in test form.
"""
import pytest

from capture.base import CaptureSource
from capture.live_source import LiveCaptureSource
from utils.exceptions import LiveCaptureNotImplementedError


def test_satisfies_capture_source_interface() -> None:
    source = LiveCaptureSource(interface="eth0")
    assert isinstance(source, CaptureSource)


def test_read_packets_raises_immediately_without_iteration() -> None:
    """The exception fires on the read_packets() call itself, not only
    when the caller starts iterating — see module docstring."""
    source = LiveCaptureSource(interface="eth0")
    with pytest.raises(LiveCaptureNotImplementedError, match="not implemented"):
        source.read_packets()


def test_works_with_no_interface_specified() -> None:
    source = LiveCaptureSource(interface=None)
    with pytest.raises(LiveCaptureNotImplementedError):
        source.read_packets()