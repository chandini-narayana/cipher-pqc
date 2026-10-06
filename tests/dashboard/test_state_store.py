"""Tests for dashboard.state_store — the lock-protected snapshot publisher
that appliance mode uses (docs/SDD.md Phase A1 addendum).

No server, no thread-per-test except where concurrency is the thing under
test, and no hardware.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pytest

from dashboard.state import ApplicationState, build_application_state
from dashboard.state_store import ApplicationStateStore, resolve_state_store
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.report_metadata import ReportMetadata
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _assessment(
    ip: str,
    risk_score: int = 9,
    category: RiskCategory = RiskCategory.HIGH,
    isolation: Optional[IsolationStatus] = None,
    assessed_at: datetime = TS,
) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(risk_score, category, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=category,
        assessed_at=assessed_at,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


def _report(ip: str, report_id: str = "CIPHER-x-1"):
    metadata = ReportMetadata(
        report_id, ip, TS, 3, "ab" * 32, "cd" * 32, "Dilithium2", "Verified"
    )
    return (Path(f"/fake/{report_id}.pdf"), metadata)


# --- construction ---------------------------------------------------------


def test_a_new_store_publishes_an_empty_state() -> None:
    """So the dashboard is reachable before the first cycle finishes."""
    state = ApplicationStateStore().get()
    assert state.devices_assessed == 0
    assert state.reports_generated == 0


def test_a_store_can_be_seeded_with_an_existing_state() -> None:
    seeded = build_application_state([_assessment("10.0.0.5")], [])
    assert ApplicationStateStore(seeded).get() is seeded


# --- accumulation ---------------------------------------------------------


def test_a_first_cycle_publishes_its_devices() -> None:
    store = ApplicationStateStore()

    state = store.publish_cycle([_assessment("10.0.0.5"), _assessment("10.0.0.6")], [])

    assert set(state.assessments_by_ip) == {"10.0.0.5", "10.0.0.6"}


def test_a_later_cycle_adds_new_devices_without_losing_old_ones() -> None:
    store = ApplicationStateStore()
    store.publish_cycle([_assessment("10.0.0.5")], [])

    state = store.publish_cycle([_assessment("10.0.0.6")], [])

    assert set(state.assessments_by_ip) == {"10.0.0.5", "10.0.0.6"}


def test_a_device_absent_from_a_cycle_is_retained() -> None:
    """A quiet device has not stopped existing; it just sent nothing in the
    last few seconds."""
    store = ApplicationStateStore()
    store.publish_cycle([_assessment("10.0.0.5")], [])

    state = store.publish_cycle([], [])

    assert "10.0.0.5" in state.assessments_by_ip


def test_an_empty_cycle_does_not_clear_reports() -> None:
    store = ApplicationStateStore()
    store.publish_cycle([_assessment("10.0.0.5")], [_report("10.0.0.5")])

    state = store.publish_cycle([], [])

    assert state.reports_generated == 1


def test_many_cycles_accumulate() -> None:
    store = ApplicationStateStore()

    for index in range(5):
        store.publish_cycle([_assessment(f"10.0.0.{index}")], [])

    assert store.get().devices_assessed == 5


# --- replacement ----------------------------------------------------------


def test_a_reassessed_device_replaces_its_previous_entry() -> None:
    store = ApplicationStateStore()
    store.publish_cycle([_assessment("10.0.0.5", risk_score=3, category=RiskCategory.MEDIUM)], [])

    state = store.publish_cycle(
        [_assessment("10.0.0.5", risk_score=9, category=RiskCategory.HIGH)], []
    )

    assert state.devices_assessed == 1  # replaced, not duplicated
    assert state.assessments_by_ip["10.0.0.5"].risk_assessment.risk_score == 9
    assert state.assessments_by_ip["10.0.0.5"].final_category is RiskCategory.HIGH


def test_the_newest_assessment_wins_even_if_it_is_lower_risk() -> None:
    """The store is a publisher, not a policy: it never decides that an
    older, higher-risk assessment should be kept."""
    store = ApplicationStateStore()
    store.publish_cycle([_assessment("10.0.0.5", 9, RiskCategory.HIGH)], [])

    state = store.publish_cycle([_assessment("10.0.0.5", 1, RiskCategory.LOW)], [])

    assert state.assessments_by_ip["10.0.0.5"].final_category is RiskCategory.LOW


# --- isolation state ------------------------------------------------------


def test_isolation_state_from_run_capture_is_preserved() -> None:
    isolation = IsolationStatus(
        requested=True,
        enforced=True,
        backend="linux-iptables",
        reason="isolated",
        requested_at=TS,
        enforcement_capable=True,
    )
    store = ApplicationStateStore()

    state = store.publish_cycle([_assessment("10.0.0.5", isolation=isolation)], [])

    published = state.assessments_by_ip["10.0.0.5"].isolation
    assert published is not None
    assert published.enforced is True
    assert published.backend == "linux-iptables"


def test_a_later_cycle_updates_a_devices_isolation_state() -> None:
    noop = IsolationStatus(True, False, "noop", "unavailable", TS, False)
    enforced = IsolationStatus(True, True, "linux-iptables", "isolated", TS, True)
    store = ApplicationStateStore()
    store.publish_cycle([_assessment("10.0.0.5", isolation=noop)], [])

    state = store.publish_cycle([_assessment("10.0.0.5", isolation=enforced)], [])

    assert state.assessments_by_ip["10.0.0.5"].isolation.enforced is True


# --- reports --------------------------------------------------------------


def test_a_report_is_keyed_by_the_metadata_device_ip() -> None:
    """Exactly how build_application_state keys it."""
    store = ApplicationStateStore()

    state = store.publish_cycle([], [_report("10.0.0.5")])

    assert state.get_report("10.0.0.5") is not None


def test_the_latest_report_per_device_is_retained() -> None:
    store = ApplicationStateStore()
    store.publish_cycle([], [_report("10.0.0.5", "CIPHER-old")])

    state = store.publish_cycle([], [_report("10.0.0.5", "CIPHER-new")])

    assert state.reports_generated == 1
    _path, metadata = state.get_report("10.0.0.5")
    assert metadata.report_id == "CIPHER-new"


def test_reports_for_different_devices_coexist() -> None:
    store = ApplicationStateStore()
    store.publish_cycle([], [_report("10.0.0.5", "a")])

    state = store.publish_cycle([], [_report("10.0.0.6", "b")])

    assert state.reports_generated == 2


# --- publication semantics ------------------------------------------------


def test_publish_replaces_the_whole_snapshot() -> None:
    store = ApplicationStateStore()
    store.publish_cycle([_assessment("10.0.0.5")], [])
    replacement = build_application_state([_assessment("10.0.0.9")], [])

    store.publish(replacement)

    assert store.get() is replacement


def test_a_published_state_is_never_mutated_by_a_later_cycle() -> None:
    """The core safety invariant: a request thread holding an earlier
    snapshot must not see it change underneath, which is what would risk
    "dictionary changed size during iteration"."""
    store = ApplicationStateStore()
    first = store.publish_cycle([_assessment("10.0.0.5")], [_report("10.0.0.5")])
    first_devices = dict(first.assessments_by_ip)
    first_reports = dict(first.reports_by_ip)

    store.publish_cycle([_assessment("10.0.0.6")], [_report("10.0.0.6")])

    assert first.assessments_by_ip == first_devices
    assert first.reports_by_ip == first_reports


def test_each_cycle_publishes_a_distinct_state_object() -> None:
    store = ApplicationStateStore()
    first = store.publish_cycle([_assessment("10.0.0.5")], [])
    second = store.publish_cycle([_assessment("10.0.0.6")], [])

    assert first is not second
    assert first.assessments_by_ip is not second.assessments_by_ip


def test_publish_cycle_returns_the_state_it_published() -> None:
    store = ApplicationStateStore()
    returned = store.publish_cycle([_assessment("10.0.0.5")], [])
    assert returned is store.get()


# --- explicit synchronisation --------------------------------------------


def test_the_store_uses_an_explicit_lock() -> None:
    """The concurrency contract must not rest on the GIL making an
    assignment atomic; an explicit lock is the contract."""
    store = ApplicationStateStore()
    assert isinstance(store._lock, type(threading.Lock()))


def test_concurrent_readers_and_a_writer_never_observe_a_broken_snapshot() -> None:
    """A writer republishing in a loop while readers iterate every snapshot:
    no reader may raise, and every snapshot must be self-consistent."""
    store = ApplicationStateStore()
    errors = []
    stop = threading.Event()

    def _write() -> None:
        try:
            for index in range(300):
                store.publish_cycle([_assessment(f"10.1.{index // 256}.{index % 256}")], [])
        except Exception as exc:  # pragma: no cover - a failure is the finding
            errors.append(exc)
        finally:
            stop.set()

    def _read() -> None:
        try:
            while not stop.is_set():
                snapshot = store.get()
                # Iterating is exactly what a request does via
                # list_assessments(); a mutated snapshot would raise here.
                listed = snapshot.list_assessments()
                assert len(listed) == snapshot.devices_assessed
        except Exception as exc:  # pragma: no cover - a failure is the finding
            errors.append(exc)

    threads = [threading.Thread(target=_write)] + [
        threading.Thread(target=_read) for _ in range(3)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert errors == []


# --- resolve_state_store --------------------------------------------------


def test_resolve_wraps_a_plain_application_state() -> None:
    """Backward compatibility for every existing create_app caller."""
    state = build_application_state([_assessment("10.0.0.5")], [])
    store = resolve_state_store(state)

    assert isinstance(store, ApplicationStateStore)
    assert store.get() is state


def test_resolve_passes_a_store_through_unchanged() -> None:
    store = ApplicationStateStore()
    assert resolve_state_store(store) is store


@pytest.mark.parametrize("value", [None, "state", 42, {}])
def test_resolve_rejects_anything_else(value) -> None:
    with pytest.raises(TypeError):
        resolve_state_store(value)


def test_an_empty_application_state_is_valid() -> None:
    assert ApplicationState().devices_assessed == 0
