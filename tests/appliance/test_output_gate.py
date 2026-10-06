"""Tests for appliance.output_gate — the shutdown barrier between the capture
worker's hardware writes and releasing that hardware.

No real hardware: the display and LED doubles only record calls. The
concurrency tests use real threads, because the ordering between a worker
mid-write and a main thread closing is precisely what is under test.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import List, Optional

import pytest

from appliance.output_gate import DEFAULT_CLOSE_TIMEOUT_SECONDS, HardwareOutputGate
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _assessment(ip: str = "10.0.0.5") -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )


def _safe_call(action: str, call, *args) -> None:
    """Stands in for run_pi_live._safe_display: swallows anything raised."""
    try:
        call(*args)
    except Exception:  # noqa: BLE001 - that is the helper's whole job
        pass


class _Devices:
    """Records observer writes and close() calls for both output devices."""

    def __init__(self) -> None:
        self.writes: List[str] = []
        self.closed: List[str] = []

    def observer(self, assessment: DeviceAssessment) -> None:
        self.writes.append(assessment.device.ip)

    def close_calls(self):
        return [
            ("shutdown", lambda: self.closed.append("display")),
            ("LED shutdown", lambda: self.closed.append("leds")),
        ]


def _gate(devices: _Devices, observer=None, timeout: float = 5.0) -> HardwareOutputGate:
    return HardwareOutputGate(
        observer=observer or devices.observer,
        close_calls=devices.close_calls(),
        safe_call=_safe_call,
        timeout=timeout,
    )


# --- pass-through while open ----------------------------------------------


def test_the_observer_is_called_while_the_gate_is_open() -> None:
    devices = _Devices()
    gate = _gate(devices)

    gate.observe(_assessment("10.0.0.5"))

    assert devices.writes == ["10.0.0.5"]


def test_the_gate_adds_nothing_to_what_is_shown() -> None:
    """It wraps the existing fan-out; it does not reinterpret an assessment."""
    seen = []
    devices = _Devices()
    gate = _gate(devices, observer=seen.append)

    assessment = _assessment()
    gate.observe(assessment)

    assert seen == [assessment]


def test_a_new_gate_is_open_and_has_released_nothing() -> None:
    gate = _gate(_Devices())
    assert gate.closed is False
    assert gate.devices_released is False


def test_an_observer_that_raises_cannot_escape() -> None:
    def _boom(_assessment):
        raise RuntimeError("panel exploded mid-write")

    gate = _gate(_Devices(), observer=_boom)

    gate.observe(_assessment())  # must not raise


def test_an_observer_that_raises_does_not_jam_the_gate() -> None:
    """A failed write must still release the lock, or shutdown would hang."""

    def _boom(_assessment):
        raise RuntimeError("panel exploded mid-write")

    devices = _Devices()
    gate = _gate(devices, observer=_boom)
    gate.observe(_assessment())

    assert gate.close() is True
    assert devices.closed == ["display", "leds"]


# --- close disables output, then releases ---------------------------------


def test_close_releases_both_devices_in_order() -> None:
    devices = _Devices()
    gate = _gate(devices)

    assert gate.close() is True

    assert devices.closed == ["display", "leds"]
    assert gate.devices_released is True


def test_close_disables_further_output() -> None:
    devices = _Devices()
    gate = _gate(devices)
    gate.close()

    gate.observe(_assessment("10.9.9.9"))

    assert devices.writes == []


def test_output_is_disabled_even_when_release_is_skipped() -> None:
    """The flag is set before the wait, so a timed-out close still stops all
    further writes."""
    devices = _Devices()
    gate = _gate(devices, timeout=0.05)
    gate._lock.acquire()  # simulate a write that never finishes
    try:
        assert gate.close() is False
    finally:
        gate._lock.release()

    assert gate.closed is True
    gate.observe(_assessment())
    assert devices.writes == []


def test_a_timed_out_close_does_not_release_the_devices() -> None:
    """Closing underneath a live writer is exactly the race to avoid: better
    to leave the devices open and say so."""
    devices = _Devices()
    gate = _gate(devices, timeout=0.05)
    gate._lock.acquire()
    try:
        released = gate.close()
    finally:
        gate._lock.release()

    assert released is False
    assert devices.closed == []
    assert gate.devices_released is False


def test_a_timed_out_close_is_logged_with_its_reason(caplog) -> None:
    gate = _gate(_Devices(), timeout=0.05)
    gate._lock.acquire()
    try:
        with caplog.at_level(logging.WARNING, logger="appliance.output_gate"):
            gate.close()
    finally:
        gate._lock.release()

    message = " ".join(record.getMessage() for record in caplog.records)
    assert "NOT closed" in message
    assert "daemon" in message


def test_close_is_bounded_by_its_timeout() -> None:
    """Shutdown must stay prompt enough for a service manager."""
    import time

    gate = _gate(_Devices(), timeout=0.2)
    gate._lock.acquire()
    try:
        started = time.monotonic()
        gate.close()
        elapsed = time.monotonic() - started
    finally:
        gate._lock.release()

    assert elapsed < 2.0


def test_the_default_timeout_is_short() -> None:
    assert 0 < DEFAULT_CLOSE_TIMEOUT_SECONDS <= 10


# --- idempotence and robustness -------------------------------------------


def test_close_is_idempotent() -> None:
    devices = _Devices()
    gate = _gate(devices)

    gate.close()
    gate.close()

    assert devices.closed == ["display", "leds"]


def test_a_second_close_after_a_timed_out_one_can_still_release() -> None:
    """A retry once the write has finished must be able to finish the job."""
    devices = _Devices()
    gate = _gate(devices, timeout=0.05)
    gate._lock.acquire()
    assert gate.close() is False
    gate._lock.release()

    assert gate.close() is True
    assert devices.closed == ["display", "leds"]


def test_a_device_that_raises_on_close_does_not_stop_the_other() -> None:
    devices = _Devices()

    def _hostile():
        raise RuntimeError("panel exploded on close")

    gate = HardwareOutputGate(
        observer=devices.observer,
        close_calls=[("shutdown", _hostile), ("LED shutdown", lambda: devices.closed.append("leds"))],
        safe_call=_safe_call,
    )

    assert gate.close() is True
    assert devices.closed == ["leds"]


# --- concurrency: the actual race ----------------------------------------


def test_close_waits_for_an_in_flight_write_to_finish() -> None:
    """The ordering guarantee: a device is never released while a write is
    still running."""
    devices = _Devices()
    write_started = threading.Event()
    release_write = threading.Event()
    events: List[str] = []

    def _slow_observer(_assessment):
        events.append("write-start")
        write_started.set()
        release_write.wait(timeout=5)
        events.append("write-end")

    gate = _gate(devices, observer=_slow_observer)

    writer = threading.Thread(target=lambda: gate.observe(_assessment()))
    writer.start()
    assert write_started.wait(timeout=5)

    closer_done = threading.Event()

    def _close():
        gate.close()
        events.append("closed")
        closer_done.set()

    closer = threading.Thread(target=_close)
    closer.start()

    # The closer must still be waiting: the write has not finished.
    assert closer_done.wait(timeout=0.3) is False
    assert "closed" not in events

    release_write.set()
    writer.join(timeout=5)
    closer.join(timeout=5)

    assert events == ["write-start", "write-end", "closed"]
    assert devices.closed == ["display", "leds"]


def test_a_write_starting_during_close_is_dropped_not_executed() -> None:
    """The second check under the lock: a write that arrives between the flag
    being set and the lock being taken must not slip through."""
    devices = _Devices()
    gate = _gate(devices)
    gate.close()

    threads = [threading.Thread(target=lambda: gate.observe(_assessment())) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert devices.writes == []


def test_a_busy_writer_loop_stops_writing_once_the_gate_closes() -> None:
    """What a still-running worker actually looks like: a loop calling the
    observer. After close() it must stop touching hardware, which is what lets
    shutdown release the devices safely even with the worker alive."""
    devices = _Devices()
    gate = _gate(devices)
    stop = threading.Event()

    def _busy():
        while not stop.is_set():
            gate.observe(_assessment())

    writer = threading.Thread(target=_busy)
    writer.start()
    try:
        assert gate.close() is True
        writes_at_close = len(devices.writes)
        # Give the loop time to keep trying; none of it may reach the device.
        for _ in range(1000):
            gate.observe(_assessment())
        assert len(devices.writes) == writes_at_close
    finally:
        stop.set()
        writer.join(timeout=5)

    assert devices.closed == ["display", "leds"]
    assert len(devices.writes) == writes_at_close


def test_concurrent_closes_release_the_devices_once() -> None:
    devices = _Devices()
    gate = _gate(devices)

    threads = [threading.Thread(target=gate.close) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert devices.closed == ["display", "leds"]


# --- no new runtime -------------------------------------------------------


def test_the_gate_uses_only_a_lock_and_a_flag() -> None:
    """Smallest explicit synchronisation: no executor, queue, timer or
    service framework."""
    import ast
    import inspect

    import appliance.output_gate as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    for forbidden in ("asyncio", "concurrent", "queue", "multiprocessing", "signal", "sched"):
        assert forbidden not in imported
