"""Unit tests for capture.offline_source.OfflinePcapSource.

Uses the committed fixture generator (tests/fixtures/generate_fixtures.py),
auto-materialized by tests/conftest.py — deterministic, no live network
or elevated privileges required.
"""
from pathlib import Path

import pytest

from capture.offline_source import OfflinePcapSource
from capture.raw_packet import RawPacket
from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH
from utils.exceptions import CaptureError


def test_missing_file_raises_capture_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.pcap"
    with pytest.raises(CaptureError, match="not found"):
        OfflinePcapSource(missing)


def test_reads_expected_packets_from_fixture() -> None:
    source = OfflinePcapSource(SAMPLE_PCAP_PATH)
    packets = list(source.read_packets())

    # Fixture has 5 packets total; only the 3 with an IP layer AND a
    # non-empty TCP/UDP payload should be yielded (see generator docstring).
    assert len(packets) == 3
    assert all(isinstance(p, RawPacket) for p in packets)


def test_filters_out_empty_payload_and_non_ip_packets() -> None:
    source = OfflinePcapSource(SAMPLE_PCAP_PATH)
    packets = list(source.read_packets())

    dst_ports = {p.dst_port for p in packets}
    # Port 22 (the empty-payload TCP packet) must not appear.
    assert 22 not in dst_ports
    # The three expected destination ports are present.
    assert dst_ports == {443, 80, 1883}


def test_extracted_packet_fields_are_correct() -> None:
    source = OfflinePcapSource(SAMPLE_PCAP_PATH)
    packets = list(source.read_packets())

    tls_like = next(p for p in packets if p.dst_port == 443)
    assert tls_like.src_ip == "192.168.1.10"
    assert tls_like.dst_ip == "192.168.1.1"
    assert tls_like.src_port == 51000
    assert tls_like.payload.startswith(b"\x16\x03\x03")


def test_read_packets_is_a_fresh_generator_each_call() -> None:
    """Streaming, not bulk-loaded (see docs/SDD.md Section 16) — calling
    read_packets() twice should independently re-read the file."""
    source = OfflinePcapSource(SAMPLE_PCAP_PATH)
    first_pass = list(source.read_packets())
    second_pass = list(source.read_packets())
    assert len(first_pass) == len(second_pass) == 3