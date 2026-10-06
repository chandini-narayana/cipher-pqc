"""Tests for appliance.worker — the repeated bounded-capture loop
(docs/SDD.md Phase A1 addendum).

Everything is injected: the capture source factory and `run_capture` itself
are fakes, so no interface, capture backend, root privilege or hardware is
involved, and no real packet is ever read.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pytest

from appliance.worker import (
    DEFAULT_CYCLE_SECONDS,
    MIN_CYCLE_SECONDS,
    ApplianceCaptureWorker,
)
from dashboard.state_store import ApplicationStateStore
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.report_metadata import ReportMetadata
from models.risk_assessment import RiskAssessment
from utils.exceptions import CaptureError, CipherError

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _assessment(ip: str, isolation: Optional[IsolationStatus] = None) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


def _report(ip: str, report_id: str = "CIPHER-x"):
    return (
        Path(f"/fake/{report_id}.pdf"),
        ReportMetadata(report_id, ip, TS, 3, "ab" * 32, "cd" * 32, "Dilithium2", "Verified"),
    )


class _FakeSource:
    def __init__(self, index: int) -> None:
        self.index = index


class _Harness:
    """Records every cycle and returns scripted results."""

    def __init__(self, results=None) -> None:
        self.sources: List[_FakeSource] = []
        self.capture_calls: List[dict] = []
        self._results = list(results or [])
        self._built = 0

    def source_factory(self) -> _FakeSource:
        source = _FakeSource(self._built)
        self._built += 1
        self.sources.append(source)
        return source

    def run_capture(self, capture_source, **kwargs):
        self.capture_calls.append({"source": capture_source, **kwargs})
        if self._results:
            return self._results.pop(0)
        return ([], [])


def _worker(harness: _Harness, store: Optional[ApplicationStateStore] = None, **kwargs):
    return ApplianceCaptureWorker(
        store=store or ApplicationStateStore(),
        source_factory=harness.source_factory,
        run_capture_fn=harness.run_capture,
        **kwargs,
    )


# --- cycle length validation ----------------------------------------------


def test_the_default_cycle_is_five_seconds() -> None:
    assert DEFAULT_CYCLE_SECONDS == 5.0


def test_a_cycle_shorter_than_the_minimum_is_refused() -> None:
    """Report filenames carry a whole-second timestamp, so a sub-second
    cycle would overwrite a device's previous signed PDF."""
    with pytest.raises(CipherError) as excinfo:
        _worker(_Harness(), cycle_seconds=0.5)

    assert "report filenames" in str(excinfo.value)


def test_the_minimum_cycle_is_accepted() -> None:
    _worker(_Harness(), cycle_seconds=MIN_CYCLE_SECONDS)  # must not raise


def test_the_default_cycle_is_accepted() -> None:
    _worker(_Harness())  # must not raise


# --- one cycle ------------------------------------------------------------


def test_a_cycle_builds_a_source_and_runs_the_pipeline() -> None:
    harness = _Harness()
    worker = _worker(harness)

    assert worker.run_cycle() is True
    assert len(harness.sources) == 1
    assert len(harness.capture_calls) == 1


def test_the_composed_capture_arguments_are_passed_through_unchanged() -> None:
    """The worker adds nothing to and removes nothing from the pipeline
    call — including the observer that drives the OLED and LEDs."""
    harness = _Harness()
    observer = lambda assessment: None  # noqa: E731 - a stand-in callable
    worker = _worker(
        harness,
        capture_kwargs={
            "anomaly_detector": "detector",
            "public_key": b"pk",
            "secret_key": b"sk",
            "isolation_backend": "backend",
            "risk_isolation_threshold": 7,
            "assessment_observer": observer,
        },
    )

    worker.run_cycle()

    call = harness.capture_calls[0]
    assert call["anomaly_detector"] == "detector"
    assert call["isolation_backend"] == "backend"
    assert call["risk_isolation_threshold"] == 7
    assert call["assessment_observer"] is observer


def test_a_cycles_results_are_published() -> None:
    store = ApplicationStateStore()
    harness = _Harness(results=[([_assessment("10.0.0.5")], [_report("10.0.0.5")])])
    worker = _worker(harness, store=store)

    worker.run_cycle()

    state = store.get()
    assert state.devices_assessed == 1
    assert state.reports_generated == 1


def test_isolation_state_reaches_the_store_untouched() -> None:
    isolation = IsolationStatus(True, True, "linux-iptables", "isolated", TS, True)
    store = ApplicationStateStore()
    harness = _Harness(results=[([_assessment("10.0.0.5", isolation)], [])])

    _worker(harness, store=store).run_cycle()

    assert store.get().assessments_by_ip["10.0.0.5"].isolation.enforced is True


def test_a_completed_cycle_is_counted() -> None:
    worker = _worker(_Harness())
    worker.run_cycle()
    assert (worker.cycles_completed, worker.cycles_failed) == (1, 0)


# --- repeated cycles ------------------------------------------------------


def test_a_fresh_source_is_built_for_every_cycle() -> None:
    """A reused NetworkLiveCaptureSource would accumulate its counters
    across read_packets() calls, turning per-cycle figures into run totals."""
    harness = _Harness()
    worker = _worker(harness)

    worker.run_cycle()
    worker.run_cycle()
    worker.run_cycle()

    assert len(harness.sources) == 3
    assert len({id(source) for source in harness.sources}) == 3


def test_repeated_cycles_accumulate_state() -> None:
    store = ApplicationStateStore()
    harness = _Harness(
        results=[
            ([_assessment("10.0.0.5")], []),
            ([_assessment("10.0.0.6")], []),
            ([], []),
        ]
    )
    worker = _worker(harness, store=store)

    for _ in range(3):
        worker.run_cycle()

    assert set(store.get().assessments_by_ip) == {"10.0.0.5", "10.0.0.6"}


def test_run_forever_loops_until_stopped() -> None:
    harness = _Harness()
    worker = _worker(harness)
    calls = {"count": 0}

    original = harness.run_capture

    def _stop_after_three(capture_source, **kwargs):
        calls["count"] += 1
        if calls["count"] >= 3:
            worker.stop()
        return original(capture_source, **kwargs)

    worker._run_capture = _stop_after_three
    worker.run_forever(sleep=lambda _seconds: None)

    assert calls["count"] == 3
    assert worker.cycles_completed == 3


def test_run_forever_does_not_start_a_cycle_when_already_stopped() -> None:
    harness = _Harness()
    worker = _worker(harness)
    worker.stop()

    worker.run_forever(sleep=lambda _seconds: None)

    assert harness.capture_calls == []


def test_an_instant_cycle_pauses_rather_than_spinning() -> None:
    """A source that fails immediately must not produce a hot loop."""
    harness = _Harness()
    worker = _worker(harness)
    slept = []
    calls = {"count": 0}

    def _instant(capture_source, **kwargs):
        calls["count"] += 1
        if calls["count"] >= 2:
            worker.stop()
        return ([], [])

    worker._run_capture = _instant
    worker.run_forever(sleep=lambda seconds: slept.append(seconds))

    assert slept  # the loop paused between the instant cycles


# --- failure handling -----------------------------------------------------


def test_a_cipher_error_in_a_cycle_is_contained(caplog) -> None:
    def _failing(capture_source, **kwargs):
        raise CaptureError("interface disappeared")

    worker = _worker(_Harness())
    worker._run_capture = _failing

    with caplog.at_level(logging.ERROR, logger="appliance.worker"):
        assert worker.run_cycle() is False

    assert worker.cycles_failed == 1
    assert any("cycle failed" in record.getMessage().lower() for record in caplog.records)


def test_an_unexpected_error_in_a_cycle_is_contained() -> None:
    def _exploding(capture_source, **kwargs):
        raise RuntimeError("something nobody predicted")

    worker = _worker(_Harness())
    worker._run_capture = _exploding

    assert worker.run_cycle() is False
    assert worker.cycles_failed == 1


def test_a_failing_source_factory_is_contained() -> None:
    def _failing_factory():
        raise CaptureError("permission denied on the interface")

    worker = ApplianceCaptureWorker(
        store=ApplicationStateStore(),
        source_factory=_failing_factory,
        run_capture_fn=_Harness().run_capture,
    )

    assert worker.run_cycle() is False


def test_a_failed_cycle_does_not_destroy_previously_published_state() -> None:
    """The decisive availability property: one bad cycle must not empty the
    dashboard."""
    store = ApplicationStateStore()
    harness = _Harness(results=[([_assessment("10.0.0.5")], [_report("10.0.0.5")])])
    worker = _worker(harness, store=store)
    worker.run_cycle()

    def _failing(capture_source, **kwargs):
        raise CaptureError("interface disappeared")

    worker._run_capture = _failing
    worker.run_cycle()

    state = store.get()
    assert state.devices_assessed == 1
    assert state.reports_generated == 1


def test_the_loop_survives_a_failing_cycle_and_continues() -> None:
    worker = _worker(_Harness())
    calls = {"count": 0}

    def _fail_then_succeed(capture_source, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise CaptureError("transient failure")
        worker.stop()
        return ([_assessment("10.0.0.5")], [])

    worker._run_capture = _fail_then_succeed
    worker.run_forever(sleep=lambda _seconds: None)

    assert worker.cycles_failed == 1
    assert worker.cycles_completed == 1


# --- shutdown -------------------------------------------------------------


def test_stop_sets_the_shared_event() -> None:
    worker = _worker(_Harness())
    assert worker.stop_event.is_set() is False

    worker.stop()

    assert worker.stop_event.is_set() is True


def test_an_externally_supplied_stop_event_is_used() -> None:
    event = threading.Event()
    worker = _worker(_Harness(), stop_event=event)

    worker.stop()

    assert event.is_set() is True


def test_a_stop_requested_mid_cycle_ends_the_loop_at_the_boundary() -> None:
    worker = _worker(_Harness())
    calls = {"count": 0}

    def _stop_during_the_first_cycle(capture_source, **kwargs):
        calls["count"] += 1
        worker.stop()  # as a signal handler would, mid-cycle
        return ([], [])

    worker._run_capture = _stop_during_the_first_cycle
    worker.run_forever(sleep=lambda _seconds: None)

    assert calls["count"] == 1  # the in-flight cycle finished; no new one started


def test_the_worker_thread_is_a_daemon_and_stops_on_request() -> None:
    harness = _Harness()
    worker = _worker(harness)

    thread = worker.start_thread()
    try:
        assert thread.daemon is True
        assert thread.name == "cipher-appliance-capture"
    finally:
        worker.stop()
        thread.join(timeout=10)

    assert thread.is_alive() is False


# --- the worker is not a second pipeline ----------------------------------


def test_the_worker_module_contains_no_assessment_or_policy_logic() -> None:
    """Structural guarantee: the loop composes run_capture, it does not
    reimplement any part of it."""
    import ast
    import inspect

    import appliance.worker as module

    tree = ast.parse(inspect.getsource(module))
    identifiers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.alias):
            identifiers.add(node.name.split(".")[-1])

    for forbidden in (
        "assess_packet",
        "should_isolate",
        "fuse_assessments",
        "evaluate_risk",
        "generate_report",
        "AnomalyDetector",
        "risk_score",
        "final_category",
    ):
        assert forbidden not in identifiers
