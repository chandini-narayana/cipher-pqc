"""Unit tests for capture.raw_packet.RawPacket."""
from datetime import datetime

import pytest

from capture.raw_packet import RawPacket
from models.packet_metadata import PacketMetadata

TS = datetime(2026, 1, 1, 12, 0, 0)


def _valid_kwargs(**overrides):
    kwargs = dict(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        src_port=51000,
        dst_port=443,
        payload=b"hello",
        timestamp=TS,
    )
    kwargs.update(overrides)
    return kwargs


def test_valid_raw_packet_constructs() -> None:
    rp = RawPacket(**_valid_kwargs())
    assert rp.payload == b"hello"


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
def test_rejects_invalid_ip(field: str) -> None:
    with pytest.raises(ValueError):
        RawPacket(**_valid_kwargs(**{field: "bad-ip"}))


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
def test_rejects_out_of_range_port(field: str) -> None:
    with pytest.raises(ValueError):
        RawPacket(**_valid_kwargs(**{field: 70000}))


def test_rejects_empty_payload() -> None:
    with pytest.raises(ValueError, match="payload"):
        RawPacket(**_valid_kwargs(payload=b""))


def test_to_metadata_produces_correct_packet_metadata() -> None:
    rp = RawPacket(**_valid_kwargs(payload=b"12345"))
    metadata = rp.to_metadata()

    assert isinstance(metadata, PacketMetadata)
    assert metadata.src_ip == rp.src_ip
    assert metadata.dst_ip == rp.dst_ip
    assert metadata.src_port == rp.src_port
    assert metadata.dst_port == rp.dst_port
    assert metadata.packet_size == len(rp.payload) == 5
    assert metadata.timestamp == rp.timestamp