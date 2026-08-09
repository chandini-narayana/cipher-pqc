"""Unit tests for models.packet_metadata.PacketMetadata."""
from datetime import datetime

import pytest

from models.packet_metadata import PacketMetadata


def _valid_kwargs(**overrides):
    kwargs = dict(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        src_port=51000,
        dst_port=443,
        packet_size=512,
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )
    kwargs.update(overrides)
    return kwargs


def test_valid_packet_metadata_constructs() -> None:
    pm = PacketMetadata(**_valid_kwargs())
    assert pm.dst_port == 443


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
def test_rejects_invalid_ip(field: str) -> None:
    with pytest.raises(ValueError):
        PacketMetadata(**_valid_kwargs(**{field: "bad-ip"}))


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
def test_rejects_out_of_range_port(field: str) -> None:
    with pytest.raises(ValueError):
        PacketMetadata(**_valid_kwargs(**{field: 70000}))


def test_accepts_boundary_ports() -> None:
    pm = PacketMetadata(**_valid_kwargs(src_port=0, dst_port=65535))
    assert pm.src_port == 0
    assert pm.dst_port == 65535


def test_rejects_non_positive_packet_size() -> None:
    with pytest.raises(ValueError, match="packet_size"):
        PacketMetadata(**_valid_kwargs(packet_size=0))


def test_round_trip_serialization() -> None:
    pm1 = PacketMetadata(**_valid_kwargs())
    pm2 = PacketMetadata.from_dict(pm1.to_dict())
    assert pm1 == pm2