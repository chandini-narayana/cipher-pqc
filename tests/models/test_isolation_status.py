"""Unit tests for models.isolation_status.IsolationStatus (docs/SDD.md
Phase 3B addendum)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from models.isolation_status import (
    ENFORCED,
    FAILED,
    REQUESTED_NOT_ENFORCED,
    IsolationStatus,
)

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _status(**overrides) -> IsolationStatus:
    kwargs = {
        "requested": True,
        "enforced": False,
        "backend": "noop",
        "reason": "Hardware enforcement unavailable in current deployment",
        "requested_at": TS,
        "enforcement_capable": False,
    }
    kwargs.update(overrides)
    return IsolationStatus(**kwargs)


def test_exposes_the_five_required_fields() -> None:
    status = _status()
    assert status.requested is True
    assert status.enforced is False
    assert status.backend == "noop"
    assert status.reason
    assert status.requested_at == TS


def test_does_not_duplicate_device_ip_or_risk_score() -> None:
    """Both already live on the surrounding DeviceAssessment; two copies
    could disagree."""
    fields = set(IsolationStatus.__dataclass_fields__)
    assert "device_ip" not in fields
    assert "risk_score" not in fields


def test_enforcement_capable_defaults_to_false() -> None:
    """A capability is never claimed unless a backend asserts it."""
    status = IsolationStatus(
        requested=True, enforced=False, backend="x", reason="r", requested_at=TS
    )
    assert status.enforcement_capable is False


def test_is_immutable() -> None:
    status = _status()
    with pytest.raises(Exception):
        status.enforced = True  # type: ignore[misc]


# --- status_label: the compact display state ---


def test_label_is_enforced_when_enforcement_happened() -> None:
    assert _status(enforced=True, enforcement_capable=True).status_label == ENFORCED


def test_label_is_requested_not_enforced_for_a_non_enforcing_backend() -> None:
    """NoOp/Windows: requested, nothing enforced, and nothing failed."""
    assert _status(enforced=False, enforcement_capable=False).status_label == REQUESTED_NOT_ENFORCED


def test_label_is_failed_when_a_real_backend_did_not_enforce() -> None:
    assert _status(enforced=False, enforcement_capable=True).status_label == FAILED


def test_non_enforcing_backend_is_never_labelled_enforced() -> None:
    """The anti-overclaim rule: a NoOp outcome must never read as real
    network isolation."""
    assert _status(enforcement_capable=False).status_label != ENFORCED


# --- serialization ---


def test_round_trip_serialization() -> None:
    status = _status(enforced=True, backend="linux", enforcement_capable=True)
    assert IsolationStatus.from_dict(status.to_dict()) == status


def test_to_dict_renders_the_timestamp_as_isoformat() -> None:
    assert _status().to_dict()["requested_at"] == TS.isoformat()


def test_from_dict_tolerates_a_payload_without_enforcement_capable() -> None:
    """A payload serialized before this field existed must still load —
    and must default to the safe reading."""
    payload = _status().to_dict()
    del payload["enforcement_capable"]
    assert IsolationStatus.from_dict(payload).enforcement_capable is False
