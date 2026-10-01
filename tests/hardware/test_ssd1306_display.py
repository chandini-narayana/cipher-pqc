"""Unit tests for hardware.ssd1306_display — the optional SSD1306 I2C
adapter, driven entirely through an injected fake device.

No real I2C bus, no `luma` installation, no Raspberry Pi and no root is
required. The fake device and fake canvas capture exactly what would have
been drawn, which proves the command/data flow and every failure path
without touching hardware.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, List, Optional

import pytest

from hardware.display import StatusDisplay
from hardware.ssd1306_display import (
    DEFAULT_I2C_ADDRESS,
    DEFAULT_I2C_BUS,
    DisplayDriverUnavailableError,
    SSD1306StatusDisplay,
)
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class _FakeDraw:
    def __init__(self, sink: List[str]) -> None:
        self._sink = sink

    def text(self, position, line, fill=None) -> None:  # noqa: ANN001 - fake signature
        self._sink.append(line)


class _FakeCanvas:
    """Stands in for luma.core.render.canvas (a context manager)."""

    def __init__(self, sink: List[str]) -> None:
        self._sink = sink

    def __enter__(self) -> _FakeDraw:
        return _FakeDraw(self._sink)

    def __exit__(self, *exc_info) -> bool:
        return False


class _FakeDevice:
    def __init__(self) -> None:
        self.cleared = 0

    def clear(self) -> None:
        self.cleared += 1


class _FailingCanvas:
    def __enter__(self):
        raise OSError("[Errno 121] Remote I/O error")

    def __exit__(self, *exc_info) -> bool:
        return False


def _display(
    device: Optional[Any] = None,
    drawn: Optional[List[str]] = None,
    min_interval: float = 0.0,
    device_factory=None,
    canvas_factory=None,
    **kwargs,
) -> SSD1306StatusDisplay:
    """Build an adapter wired to fakes. `drawn` collects rendered lines."""
    fake_device = device if device is not None else _FakeDevice()
    sink = drawn if drawn is not None else []

    return SSD1306StatusDisplay(
        device_factory=device_factory or (lambda bus, address: fake_device),
        canvas_factory=canvas_factory or (lambda _device: _FakeCanvas(sink)),
        min_interval_seconds=min_interval,
        **kwargs,
    )


def _assessment(isolation: Optional[IsolationStatus] = None) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact("192.168.50.21", TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


# --- Windows / no-driver safety -------------------------------------------


def test_importing_this_module_needs_no_hardware_library() -> None:
    """The decisive Windows property: importing the adapter must not pull in
    an I2C stack. Verified by the fact this test file imported it, plus a
    static check that no hardware import exists at module level."""
    import ast
    import inspect

    import hardware.ssd1306_display as module

    tree = ast.parse(inspect.getsource(module))
    module_level = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            module_level.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module_level.add(node.module.split(".")[0])

    for forbidden in ("luma", "board", "busio", "smbus", "smbus2", "adafruit_ssd1306", "RPi"):
        assert forbidden not in module_level


def test_the_driver_import_is_lazy_and_inside_a_function() -> None:
    """`luma` may only be referenced inside a function body, so it is
    imported when a panel is actually opened and never before."""
    import ast
    import inspect

    import hardware.ssd1306_display as module

    tree = ast.parse(inspect.getsource(module))
    luma_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("luma")
    ]
    assert luma_imports, "expected the driver to be imported somewhere"

    top_level_nodes = set(tree.body)
    for node in luma_imports:
        assert node not in top_level_nodes


def test_constructing_the_adapter_opens_nothing() -> None:
    """Construction must not touch the bus; only start() may."""
    opened = []
    display = SSD1306StatusDisplay(device_factory=lambda bus, address: opened.append(1))
    assert opened == []
    assert display.available is False


def test_a_missing_driver_is_reported_not_raised(caplog) -> None:
    def _no_driver(bus, address):
        raise DisplayDriverUnavailableError("the optional SSD1306 driver is not installed")

    display = _display(device_factory=_no_driver)

    with caplog.at_level(logging.WARNING, logger="hardware.ssd1306_display"):
        started = display.start()

    assert started is False
    assert display.available is False
    assert any("unavailable" in r.getMessage().lower() for r in caplog.records)


# --- I2C configuration ----------------------------------------------------


def test_the_default_bus_and_address_are_the_standard_ones() -> None:
    assert DEFAULT_I2C_BUS == 1
    assert DEFAULT_I2C_ADDRESS == 0x3C


def test_the_bus_and_address_are_passed_to_the_driver() -> None:
    seen = {}

    def _factory(bus, address):
        seen["bus"] = bus
        seen["address"] = address
        return _FakeDevice()

    _display(device_factory=_factory).start()

    assert seen == {"bus": DEFAULT_I2C_BUS, "address": DEFAULT_I2C_ADDRESS}


def test_a_non_default_address_is_honoured() -> None:
    """Some SSD1306 boards are strapped to 0x3D."""
    seen = {}

    def _factory(bus, address):
        seen["address"] = address
        return _FakeDevice()

    _display(device_factory=_factory, bus=0, address=0x3D).start()

    assert seen["address"] == 0x3D


def test_the_adapter_is_a_status_display() -> None:
    assert isinstance(_display(), StatusDisplay)
    assert _display().display_name == "oled"


# --- successful rendering -------------------------------------------------


def test_a_successful_start_marks_the_display_available(caplog) -> None:
    display = _display()
    with caplog.at_level(logging.INFO, logger="hardware.ssd1306_display"):
        assert display.start() is True
    assert display.available is True
    assert any("ready" in r.getMessage().lower() for r in caplog.records)


def test_the_ready_frame_is_drawn() -> None:
    drawn: List[str] = []
    display = _display(drawn=drawn)
    display.start()

    display.show_ready("eth0", "iptables")

    assert "CIPHER" in drawn
    assert "Status: READY" in drawn
    assert "Capture: eth0" in drawn


def test_an_assessment_frame_is_drawn_with_isolation_state() -> None:
    drawn: List[str] = []
    display = _display(drawn=drawn)
    display.start()

    display.show_assessment(
        _assessment(
            IsolationStatus(
                requested=True,
                enforced=True,
                backend="linux-iptables",
                reason="isolated",
                requested_at=TS,
                enforcement_capable=True,
            )
        )
    )

    assert "Device: 192.168.50.21" in drawn
    assert "QRS: 9/10" in drawn
    assert "Risk: HIGH" in drawn
    assert "Isolation: ISOLATED" in drawn


def test_nothing_is_drawn_before_start() -> None:
    drawn: List[str] = []
    display = _display(drawn=drawn)

    display.show_ready("eth0", "noop")

    assert drawn == []


def test_nothing_is_drawn_after_close() -> None:
    drawn: List[str] = []
    display = _display(drawn=drawn)
    display.start()
    display.close()

    display.show_ready("eth0", "noop")

    assert drawn == []


# --- throttling and I2C traffic -------------------------------------------


def test_an_unchanged_frame_is_not_rewritten() -> None:
    """Avoids pointless I2C traffic when the state has not moved."""
    drawn: List[str] = []
    display = _display(drawn=drawn)
    display.start()

    display.show_ready("eth0", "noop")
    first = len(drawn)
    display.show_ready("eth0", "noop")

    assert len(drawn) == first


def test_rapid_updates_are_throttled() -> None:
    """A fast capture must not turn into a flood of writes."""
    drawn: List[str] = []
    display = _display(drawn=drawn, min_interval=60.0)
    display.start()

    display.show_lines(["first"])
    written_after_first = len(drawn)
    display.show_lines(["second"])
    display.show_lines(["third"])

    assert len(drawn) == written_after_first


def test_throttling_can_be_disabled_for_deterministic_use() -> None:
    drawn: List[str] = []
    display = _display(drawn=drawn, min_interval=0.0)
    display.start()

    display.show_lines(["first"])
    display.show_lines(["second"])

    assert "first" in drawn
    assert "second" in drawn


def test_only_the_panel_sized_portion_of_a_frame_is_drawn() -> None:
    drawn: List[str] = []
    display = _display(drawn=drawn)
    display.start()

    display.show_lines([f"line{index}" for index in range(12)])

    assert len(drawn) <= 5


# --- failure handling -----------------------------------------------------


def test_an_initialization_failure_is_reported_not_raised(caplog) -> None:
    def _no_device(bus, address):
        raise OSError("[Errno 2] No such file or directory: '/dev/i2c-1'")

    display = _display(device_factory=_no_device)

    with caplog.at_level(logging.WARNING, logger="hardware.ssd1306_display"):
        started = display.start()

    assert started is False
    assert display.available is False
    message = " ".join(r.getMessage() for r in caplog.records)
    assert "i2cdetect" in message


def test_a_permission_failure_is_reported_not_raised() -> None:
    def _denied(bus, address):
        raise PermissionError("[Errno 13] Permission denied: '/dev/i2c-1'")

    assert _display(device_factory=_denied).start() is False


def test_frames_after_a_failed_start_are_silently_dropped() -> None:
    def _denied(bus, address):
        raise PermissionError("Permission denied")

    drawn: List[str] = []
    display = _display(device_factory=_denied, drawn=drawn)
    display.start()

    display.show_ready("eth0", "noop")
    display.show_assessment(_assessment())
    display.close()

    assert drawn == []


def test_a_write_failure_does_not_raise_and_disables_the_display(caplog) -> None:
    display = _display(canvas_factory=lambda _device: _FailingCanvas())
    display.start()

    with caplog.at_level(logging.WARNING, logger="hardware.ssd1306_display"):
        display.show_ready("eth0", "noop")

    assert display.available is False
    assert any("write failed" in r.getMessage().lower() for r in caplog.records)


def test_a_failing_display_stops_retrying_on_every_frame() -> None:
    """One bad write disables output for the run, so a broken panel cannot
    cost a write attempt per packet."""
    attempts = {"count": 0}

    def _counting_canvas(_device):
        attempts["count"] += 1
        return _FailingCanvas()

    display = _display(canvas_factory=_counting_canvas)
    display.start()

    for _ in range(5):
        display.show_assessment(_assessment())

    assert attempts["count"] == 1


def test_close_clears_the_panel() -> None:
    device = _FakeDevice()
    display = _display(device=device)
    display.start()

    display.close()

    assert device.cleared == 1
    assert display.available is False


def test_close_survives_a_failing_clear() -> None:
    class _FailingClear:
        def clear(self):
            raise OSError("Remote I/O error")

    display = _display(device=_FailingClear())
    display.start()

    display.close()  # must not raise

    assert display.available is False


def test_close_is_safe_without_a_start() -> None:
    _display().close()


def test_close_is_idempotent() -> None:
    device = _FakeDevice()
    display = _display(device=device)
    display.start()

    display.close()
    display.close()

    assert device.cleared == 1


# --- no SPI in this phase -------------------------------------------------


def test_no_spi_support_is_present() -> None:
    """I2C only in this phase. Checked structurally: no SPI identifier is
    referenced and no SPI module is imported. (The docstring says "No SPI in
    this phase" in prose, which is the rule, not an implementation.)"""
    import ast
    import inspect

    import hardware.ssd1306_display as module

    tree = ast.parse(inspect.getsource(module))
    identifiers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id.lower())
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr.lower())
        elif isinstance(node, ast.alias):
            identifiers.add(node.name.split(".")[-1].lower())
        elif isinstance(node, ast.ImportFrom) and node.module:
            identifiers.add(node.module.lower())

    assert not any("spi" in name for name in identifiers)


def test_the_module_states_it_is_not_hardware_validated() -> None:
    """Honesty guard: the docstring must not be quietly changed to claim
    hardware validation that has not happened."""
    import hardware.ssd1306_display as module

    assert "NOT VALIDATED ON HARDWARE" in (module.__doc__ or "")
