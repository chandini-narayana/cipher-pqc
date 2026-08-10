"""Unit tests for capture.factory.get_capture_source."""
from pathlib import Path

import pytest

from capture.factory import get_capture_source
from capture.live_source import LiveCaptureSource
from capture.offline_source import OfflinePcapSource
from config.settings import Settings
from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH
from utils.exceptions import CaptureError


def test_offline_mode_returns_offline_source() -> None:
    settings = Settings(capture_mode="offline", pcap_path=SAMPLE_PCAP_PATH)
    source = get_capture_source(settings)
    assert isinstance(source, OfflinePcapSource)


def test_live_mode_returns_live_source() -> None:
    settings = Settings(capture_mode="live", live_interface="eth0")
    source = get_capture_source(settings)
    assert isinstance(source, LiveCaptureSource)


def test_mock_mode_raises_capture_error() -> None:
    settings = Settings(capture_mode="mock")
    with pytest.raises(CaptureError, match="mock"):
        get_capture_source(settings)


def test_unrecognized_mode_raises_capture_error() -> None:
    settings = Settings(capture_mode="not-a-real-mode")
    with pytest.raises(CaptureError, match="Unrecognized"):
        get_capture_source(settings)


def test_mode_is_case_insensitive() -> None:
    settings = Settings(capture_mode="OFFLINE", pcap_path=SAMPLE_PCAP_PATH)
    source = get_capture_source(settings)
    assert isinstance(source, OfflinePcapSource)