"""Unit tests for models.device.Device."""
from datetime import datetime, timedelta

import pytest

from models.device import Device


def _now() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0)


def test_valid_device_constructs() -> None:
    d = Device(ip="192.168.1.10", first_seen=_now(), last_seen=_now())
    assert d.ip == "192.168.1.10"


def test_rejects_invalid_ip() -> None:
    with pytest.raises(ValueError, match="not a valid IP address"):
        Device(ip="not-an-ip", first_seen=_now(), last_seen=_now())


def test_rejects_ipv4_out_of_range() -> None:
    with pytest.raises(ValueError):
        Device(ip="999.999.999.999", first_seen=_now(), last_seen=_now())


def test_accepts_ipv6() -> None:
    d = Device(ip="::1", first_seen=_now(), last_seen=_now())
    assert d.ip == "::1"


def test_rejects_last_seen_before_first_seen() -> None:
    now = _now()
    with pytest.raises(ValueError, match="cannot be earlier"):
        Device(ip="10.0.0.1", first_seen=now, last_seen=now - timedelta(seconds=1))


def test_first_contact_classmethod() -> None:
    now = _now()
    d = Device.first_contact("10.0.0.5", now)
    assert d.first_seen == now
    assert d.last_seen == now


def test_with_last_seen_returns_new_instance() -> None:
    d1 = Device.first_contact("10.0.0.5", _now())
    later = _now() + timedelta(minutes=5)
    d2 = d1.with_last_seen(later)
    assert d2.last_seen == later
    assert d1.last_seen != later  # original untouched (immutability)
    assert d2.first_seen == d1.first_seen


def test_device_is_immutable() -> None:
    d = Device.first_contact("10.0.0.5", _now())
    with pytest.raises(AttributeError):
        d.ip = "10.0.0.6"  # type: ignore[misc]


def test_to_dict_and_from_dict_round_trip() -> None:
    d1 = Device.first_contact("172.16.0.1", _now())
    data = d1.to_dict()
    d2 = Device.from_dict(data)
    assert d1 == d2