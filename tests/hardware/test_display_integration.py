"""Phase 3F integration tests: the status display attached to the real
pipeline, and selected by run_pi_live.py.

The point of these is the safety property: a display is optional and
passive, so a display that is absent, broken, or actively hostile must make
no difference whatsoever to capture, assessment, isolation or reporting.

No hardware, no I2C, no driver and no root is used anywhere.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator, List, Optional

import pytest

import pipeline.runner as runner_module
import run_pi_live
from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from enforcement import NoOpIsolationBackend
from hardware import (
    GPIOStatusIndicator,
    InvalidPinConfigurationError,
    NoOpStatusDisplay,
    NoOpStatusIndicator,
    SSD1306StatusDisplay,
)
from hardware.indicator import StatusIndicator as StatusIndicatorBase
from hardware.display import StatusDisplay
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.risk_assessment import RiskAssessment
from pipeline.runner import run_capture

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_KEYS = (b"public-key-bytes", b"secret-key-bytes")
_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


class _FakeCaptureSource(CaptureSource):
    def __init__(self, packets: List[RawPacket]) -> None:
        self._packets = packets

    def read_packets(self) -> Iterator[RawPacket]:
        yield from self._packets


def _raw_packet(src_ip: str) -> RawPacket:
    return RawPacket(
        src_ip=src_ip,
        dst_ip="192.168.50.1",
        src_port=51000,
        dst_port=80,
        payload=_PAYLOAD,
        timestamp=TS,
    )


def _assessment(ip: str, risk_score: int, category: RiskCategory) -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(risk_score, category, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=category,
        assessed_at=TS,
    )


class _RecordingDisplay(StatusDisplay):
    display_name = "recording"

    def __init__(self) -> None:
        self.frames: List[List[str]] = []
        self.started = False
        self.closed = False

    def start(self) -> bool:
        self.started = True
        return True

    @property
    def available(self) -> bool:
        return True

    def show_lines(self, lines: List[str]) -> None:
        self.frames.append(list(lines))

    def close(self) -> None:
        self.closed = True


class _HostileDisplay(StatusDisplay):
    """Raises on every call — the worst-case output device."""

    display_name = "hostile"

    def start(self) -> bool:
        raise RuntimeError("display start exploded")

    def show_lines(self, lines: List[str]) -> None:
        raise RuntimeError("display write exploded")

    def close(self) -> None:
        raise RuntimeError("display close exploded")


@pytest.fixture(autouse=True)
def _no_real_reports(monkeypatch):
    monkeypatch.setattr(
        runner_module, "generate_report", lambda assessment, sk, pk, output_dir: (None, None)
    )


def _patch_assess(monkeypatch, assessment_by_ip):
    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return assessment_by_ip[device.ip]

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)


# --- the observer is optional and passive ---------------------------------


def test_run_capture_works_with_no_observer_at_all(monkeypatch) -> None:
    """The default: every existing caller is unchanged."""
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH)})

    assessments, _reports = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
    )

    assert [a.device.ip for a in assessments] == ["10.0.0.5"]


def test_the_observer_receives_each_assessment(monkeypatch) -> None:
    seen: List[str] = []
    _patch_assess(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH),
            "10.0.0.6": _assessment("10.0.0.6", 2, RiskCategory.LOW),
        },
    )

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        assessment_observer=lambda a: seen.append(a.device.ip),
    )

    assert seen == ["10.0.0.5", "10.0.0.6"]


def test_a_display_observer_renders_live_frames(monkeypatch) -> None:
    display = _RecordingDisplay()
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 7, RiskCategory.HIGH)})

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        assessment_observer=display.show_assessment,
    )

    assert display.frames
    assert "QRS: 7/10" in display.frames[0]


def test_an_exploding_observer_never_breaks_the_run(monkeypatch, caplog) -> None:
    """The safety property that matters most: a broken output device costs
    no packet, no isolation decision and no report."""
    _patch_assess(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH),
            "10.0.0.6": _assessment("10.0.0.6", 2, RiskCategory.LOW),
        },
    )

    def _boom(_assessment_arg):
        raise RuntimeError("display write exploded")

    with caplog.at_level("WARNING", logger="pipeline.runner"):
        assessments, _reports = run_capture(
            _FakeCaptureSource([_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]),
            None,
            *_KEYS,
            isolation_backend=NoOpIsolationBackend(),
            assessment_observer=_boom,
        )

    assert {a.device.ip for a in assessments} == {"10.0.0.5", "10.0.0.6"}
    assert any("observer failed" in r.getMessage().lower() for r in caplog.records)


def test_the_observer_cannot_change_the_retained_assessment(monkeypatch) -> None:
    """It gets a read-only view and its return value is discarded."""
    original = _assessment("10.0.0.5", 9, RiskCategory.HIGH)
    _patch_assess(monkeypatch, {"10.0.0.5": original})

    def _tries_to_replace(_assessment_arg):
        return _assessment("10.9.9.9", 1, RiskCategory.LOW)

    assessments, _reports = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        assessment_observer=_tries_to_replace,
    )

    assert [a.device.ip for a in assessments] == ["10.0.0.5"]
    assert assessments[0].risk_assessment.risk_score == 9


def test_isolation_state_is_unaffected_by_the_observer(monkeypatch) -> None:
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH)})

    assessments, _reports = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        assessment_observer=_RecordingDisplay().show_assessment,
    )

    assert assessments[0].isolation is not None
    assert assessments[0].isolation.enforced is False


# --- run_pi_live display selection ----------------------------------------


class _FakeCounters:
    def summary(self) -> str:
        return "seen=1, yielded=1, skipped_non_ip=0, skipped_no_transport=0, parse_failures=0"


class _FakeSource:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.counters = _FakeCounters()


@pytest.fixture
def stubbed(monkeypatch):
    """Stub run_pi_live's dependencies, recording the display it used."""
    calls = {}

    def _fake_run_capture(source, detector, public_key, secret_key, backend, **kwargs):
        calls["kwargs"] = kwargs
        return [_assessment("192.168.50.21", 9, RiskCategory.HIGH)], []

    monkeypatch.setattr(run_pi_live, "NetworkLiveCaptureSource", lambda **kw: _FakeSource(**kw))
    monkeypatch.setattr(run_pi_live, "load_anomaly_detector", lambda path: None)
    monkeypatch.setattr(run_pi_live, "load_or_create_keypair", lambda path: (b"pk", b"sk"))
    monkeypatch.setattr(run_pi_live, "configure_logging", lambda settings: None)
    monkeypatch.setattr(run_pi_live, "run_capture", _fake_run_capture)
    return calls


def test_the_display_defaults_to_disabled(stubbed) -> None:
    """Nothing hardware-facing is ever enabled implicitly."""
    built = {}
    original = run_pi_live._build_status_display

    def _spy(mode):
        built["mode"] = mode
        return original(mode)

    run_pi_live._build_status_display = _spy
    try:
        assert run_pi_live.main(["--interface", "eth0"]) == 0
    finally:
        run_pi_live._build_status_display = original

    assert built["mode"] == "none"


def test_the_default_display_is_the_noop_one() -> None:
    assert isinstance(run_pi_live._build_status_display("none"), NoOpStatusDisplay)


def test_oled_is_refused_off_linux(monkeypatch, caplog) -> None:
    """A Windows run must not reach for an I2C bus even if asked."""
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Windows")

    with caplog.at_level("WARNING", logger="run_pi_live"):
        display = run_pi_live._build_status_display("oled")

    assert isinstance(display, NoOpStatusDisplay)
    assert any("requires Linux" in r.getMessage() for r in caplog.records)


def test_oled_builds_the_ssd1306_adapter_on_linux(monkeypatch) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    display = run_pi_live._build_status_display("oled")

    assert isinstance(display, SSD1306StatusDisplay)
    # Constructed, but nothing opened: the bus is only touched by start().
    assert display.available is False


def test_the_display_flag_is_accepted_and_passed_through(monkeypatch, stubbed) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")
    assert run_pi_live.main(["--interface", "eth0", "--display", "none"]) == 0


def test_the_display_may_come_from_the_environment(monkeypatch, stubbed) -> None:
    monkeypatch.setenv("CIPHER_DISPLAY", "oled")
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")
    built = {}
    original = run_pi_live._build_status_display

    def _spy(mode):
        built["mode"] = mode
        return NoOpStatusDisplay()

    run_pi_live._build_status_display = _spy
    try:
        run_pi_live.main(["--interface", "eth0"])
    finally:
        run_pi_live._build_status_display = original

    assert built["mode"] == "oled"


def test_an_explicit_flag_beats_the_display_environment(monkeypatch, stubbed) -> None:
    monkeypatch.setenv("CIPHER_DISPLAY", "oled")
    built = {}
    original = run_pi_live._build_status_display

    def _spy(mode):
        built["mode"] = mode
        return NoOpStatusDisplay()

    run_pi_live._build_status_display = _spy
    try:
        run_pi_live.main(["--interface", "eth0", "--display", "none"])
    finally:
        run_pi_live._build_status_display = original

    assert built["mode"] == "none"


def test_an_unrecognized_display_mode_is_refused(monkeypatch, stubbed, capsys) -> None:
    monkeypatch.setenv("CIPHER_DISPLAY", "eink")

    assert run_pi_live.main(["--interface", "eth0"]) == 2
    assert "Unrecognized display mode" in capsys.readouterr().err


def test_the_observer_is_wired_to_the_display(stubbed) -> None:
    run_pi_live.main(["--interface", "eth0"])
    assert "assessment_observer" in stubbed["kwargs"]


# --- lifecycle ------------------------------------------------------------


def test_the_run_completes_with_a_hostile_display(monkeypatch, stubbed) -> None:
    """start(), show_lines() and close() all raise: the run must still
    succeed, because the display is an optional output device.

    CIPHER's own displays are contractually forbidden from raising; this
    double violates that contract deliberately, to prove the runtime does
    not depend on it being honoured."""
    monkeypatch.setattr(run_pi_live, "_build_status_display", lambda mode: _HostileDisplay())

    assert run_pi_live.main(["--interface", "eth0"]) == 0


def test_a_hostile_display_is_logged_rather_than_silent(monkeypatch, stubbed, caplog) -> None:
    monkeypatch.setattr(run_pi_live, "_build_status_display", lambda mode: _HostileDisplay())

    with caplog.at_level("WARNING", logger="run_pi_live"):
        run_pi_live.main(["--interface", "eth0"])

    assert any("display" in r.getMessage().lower() for r in caplog.records)


def test_a_failing_display_start_does_not_stop_the_run(monkeypatch, stubbed) -> None:
    class _FailsToStart(_RecordingDisplay):
        def start(self) -> bool:
            return False

    display = _FailsToStart()
    monkeypatch.setattr(run_pi_live, "_build_status_display", lambda mode: display)

    assert run_pi_live.main(["--interface", "eth0"]) == 0


def test_the_display_is_closed_at_the_end_of_the_run(monkeypatch, stubbed) -> None:
    display = _RecordingDisplay()
    monkeypatch.setattr(run_pi_live, "_build_status_display", lambda mode: display)

    run_pi_live.main(["--interface", "eth0"])

    assert display.started is True
    assert display.closed is True


def test_the_run_shows_ready_then_devices_then_a_summary(monkeypatch, stubbed) -> None:
    display = _RecordingDisplay()
    monkeypatch.setattr(run_pi_live, "_build_status_display", lambda mode: display)

    run_pi_live.main(["--interface", "eth0"])

    flattened = [" | ".join(frame) for frame in display.frames]
    assert any("Status: READY" in frame for frame in flattened)
    assert any("Device: 192.168.50.21" in frame for frame in flattened)
    assert any("Status: COMPLETE" in frame for frame in flattened)


def test_the_summary_counts_only_backend_enforced_isolations(monkeypatch, stubbed) -> None:
    """The panel never decides that isolation happened."""
    display = _RecordingDisplay()
    enforced = _assessment("10.0.0.5", 9, RiskCategory.HIGH).with_isolation(
        IsolationStatus(
            requested=True,
            enforced=True,
            backend="linux-iptables",
            reason="isolated",
            requested_at=TS,
            enforcement_capable=True,
        )
    )
    high_but_not_isolated = _assessment("10.0.0.6", 10, RiskCategory.HIGH)

    run_pi_live._show_final_frames(display, [enforced, high_but_not_isolated], [])

    summary = display.frames[-1]
    assert "Devices: 2" in summary
    assert "Isolated: 1" in summary


def test_an_interrupted_run_leaves_a_stopped_frame() -> None:
    display = _RecordingDisplay()

    run_pi_live._show_final_frames(display, None, None)

    assert display.frames == [["CIPHER", "Status: STOPPED"]]


# --- Phase 3G: LED indicator integration ---------------------------------


class _RecordingIndicator(StatusIndicatorBase):
    indicator_name = "recording"

    def __init__(self) -> None:
        self.lamps: List[Optional[str]] = []
        self.started = False
        self.closed = False

    def start(self) -> bool:
        self.started = True
        return True

    @property
    def available(self) -> bool:
        return True

    def show_lamp(self, lamp: Optional[str]) -> None:
        self.lamps.append(lamp)

    def close(self) -> None:
        self.closed = True


class _HostileIndicator(StatusIndicatorBase):
    """Raises on every call - the worst-case indicator."""

    indicator_name = "hostile"

    def start(self) -> bool:
        raise RuntimeError("LED start exploded")

    def show_lamp(self, lamp: Optional[str]) -> None:
        raise RuntimeError("LED write exploded")

    def close(self) -> None:
        raise RuntimeError("LED cleanup exploded")


def test_leds_default_to_disabled(stubbed) -> None:
    """Nothing GPIO-facing is ever enabled implicitly."""
    built = {}
    original = run_pi_live._build_status_indicator

    def _spy(mode, pins_raw):
        built["mode"] = mode
        return original(mode, pins_raw)

    run_pi_live._build_status_indicator = _spy
    try:
        assert run_pi_live.main(["--interface", "eth0"]) == 0
    finally:
        run_pi_live._build_status_indicator = original

    assert built["mode"] == "none"


def test_the_default_indicator_is_the_noop_one() -> None:
    assert isinstance(run_pi_live._build_status_indicator("none", None), NoOpStatusIndicator)


def test_gpio_leds_are_refused_off_linux(monkeypatch, caplog) -> None:
    """A Windows run must not reach for a GPIO pin even if asked."""
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Windows")

    with caplog.at_level("WARNING", logger="run_pi_live"):
        indicator = run_pi_live._build_status_indicator("gpio", "17,27,22")

    assert isinstance(indicator, NoOpStatusIndicator)
    assert any("requires Linux" in r.getMessage() for r in caplog.records)


def test_gpio_leds_build_the_adapter_on_linux(monkeypatch) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    indicator = run_pi_live._build_status_indicator("gpio", "17,27,22")

    assert isinstance(indicator, GPIOStatusIndicator)
    assert indicator.pins == {"green": 17, "amber": 27, "red": 22}
    # Constructed, but no pin acquired: only start() does that.
    assert indicator.available is False


def test_gpio_leds_require_explicit_pins(monkeypatch) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    with pytest.raises(InvalidPinConfigurationError):
        run_pi_live._build_status_indicator("gpio", None)


@pytest.mark.parametrize("raw", ["17,27", "17,27,22,23", "a,b,c", "17;27;22", ""])
def test_a_malformed_pin_list_is_rejected(monkeypatch, raw) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    with pytest.raises(InvalidPinConfigurationError):
        run_pi_live._build_status_indicator("gpio", raw)


def test_duplicate_pins_are_rejected_at_composition(monkeypatch) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    with pytest.raises(InvalidPinConfigurationError):
        run_pi_live._build_status_indicator("gpio", "17,17,22")


def test_an_invalid_pin_configuration_exits_with_a_clear_message(
    monkeypatch, stubbed, capsys
) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    exit_code = run_pi_live.main(
        ["--interface", "eth0", "--leds", "gpio", "--led-pins", "17,17,22"]
    )

    assert exit_code == 2
    assert "Invalid LED configuration" in capsys.readouterr().err


def test_leds_may_be_selected_from_the_environment(monkeypatch, stubbed) -> None:
    monkeypatch.setenv("CIPHER_LEDS", "gpio")
    monkeypatch.setenv("CIPHER_LED_PINS", "5,6,13")
    built = {}
    original = run_pi_live._build_status_indicator

    def _spy(mode, pins_raw):
        built["mode"] = mode
        built["pins"] = pins_raw
        return NoOpStatusIndicator()

    run_pi_live._build_status_indicator = _spy
    try:
        run_pi_live.main(["--interface", "eth0"])
    finally:
        run_pi_live._build_status_indicator = original

    assert built["mode"] == "gpio"
    assert built["pins"] == "5,6,13"


def test_an_explicit_led_flag_beats_the_environment(monkeypatch, stubbed) -> None:
    monkeypatch.setenv("CIPHER_LEDS", "gpio")
    built = {}
    original = run_pi_live._build_status_indicator

    def _spy(mode, pins_raw):
        built["mode"] = mode
        return NoOpStatusIndicator()

    run_pi_live._build_status_indicator = _spy
    try:
        run_pi_live.main(["--interface", "eth0", "--leds", "none"])
    finally:
        run_pi_live._build_status_indicator = original

    assert built["mode"] == "none"


def test_an_unrecognized_led_mode_is_refused(monkeypatch, stubbed, capsys) -> None:
    monkeypatch.setenv("CIPHER_LEDS", "neopixel")

    assert run_pi_live.main(["--interface", "eth0"]) == 2
    assert "Unrecognized LED mode" in capsys.readouterr().err


# --- LED lifecycle through the runtime -----------------------------------


def test_the_indicator_is_started_and_closed(monkeypatch, stubbed) -> None:
    indicator = _RecordingIndicator()
    monkeypatch.setattr(run_pi_live, "_build_status_indicator", lambda mode, pins: indicator)

    run_pi_live.main(["--interface", "eth0"])

    assert indicator.started is True
    assert indicator.closed is True


def test_the_leds_start_off_and_end_off(monkeypatch, stubbed) -> None:
    """The LEDs are a LIVE indicator, driven by the assessment observer
    during capture (covered below). The run itself only brackets them: all
    off at ready, and off again at shutdown, so a lamp is never left
    asserting a risk state for a run that has finished."""
    indicator = _RecordingIndicator()
    monkeypatch.setattr(run_pi_live, "_build_status_indicator", lambda mode, pins: indicator)

    run_pi_live.main(["--interface", "eth0"])

    assert indicator.lamps[0] is None
    assert indicator.closed is True


def test_a_hostile_indicator_does_not_stop_the_run(monkeypatch, stubbed) -> None:
    """start(), show_lamp() and close() all raise: the run must still
    succeed, because the LEDs are an optional output device."""
    monkeypatch.setattr(
        run_pi_live, "_build_status_indicator", lambda mode, pins: _HostileIndicator()
    )

    assert run_pi_live.main(["--interface", "eth0"]) == 0


def test_a_failing_indicator_does_not_stop_the_oled(monkeypatch, stubbed) -> None:
    """Each output device is wrapped separately, so one failing cannot
    silence the other."""
    display = _RecordingDisplay()
    monkeypatch.setattr(run_pi_live, "_build_status_display", lambda mode: display)
    monkeypatch.setattr(
        run_pi_live, "_build_status_indicator", lambda mode, pins: _HostileIndicator()
    )

    assert run_pi_live.main(["--interface", "eth0"]) == 0
    flattened = [" | ".join(frame) for frame in display.frames]
    assert any("Device: 192.168.50.21" in frame for frame in flattened)


def test_a_failing_oled_does_not_stop_the_leds(monkeypatch) -> None:
    """Each output device is wrapped separately, so an exploding OLED
    cannot stop the LEDs from being updated."""
    indicator = _RecordingIndicator()
    observer = run_pi_live._build_assessment_observer(_HostileDisplay(), indicator)

    observer(_assessment("10.0.0.5", 9, RiskCategory.HIGH))

    assert indicator.lamps == ["red"]


def test_a_failing_oled_does_not_stop_a_full_led_run(monkeypatch, stubbed) -> None:
    indicator = _RecordingIndicator()
    monkeypatch.setattr(run_pi_live, "_build_status_display", lambda mode: _HostileDisplay())
    monkeypatch.setattr(run_pi_live, "_build_status_indicator", lambda mode, pins: indicator)

    assert run_pi_live.main(["--interface", "eth0"]) == 0
    assert indicator.started is True
    assert indicator.closed is True


def test_the_observer_updates_both_output_devices() -> None:
    """One assessment, both devices, through the single existing hook - no
    second packet-processing path was added."""
    display = _RecordingDisplay()
    indicator = _RecordingIndicator()
    observer = run_pi_live._build_assessment_observer(display, indicator)

    observer(_assessment("10.0.0.5", 9, RiskCategory.HIGH))

    assert display.frames
    assert indicator.lamps == ["red"]


def test_the_observer_runs_through_the_existing_pipeline_hook(monkeypatch) -> None:
    display = _RecordingDisplay()
    indicator = _RecordingIndicator()
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 5, RiskCategory.MEDIUM)})

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        assessment_observer=run_pi_live._build_assessment_observer(display, indicator),
    )

    assert indicator.lamps == ["amber"]
    assert display.frames


def test_an_exploding_indicator_cannot_break_the_pipeline(monkeypatch) -> None:
    display = _RecordingDisplay()
    _patch_assess(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH),
            "10.0.0.6": _assessment("10.0.0.6", 2, RiskCategory.LOW),
        },
    )

    assessments, _reports = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        assessment_observer=run_pi_live._build_assessment_observer(display, _HostileIndicator()),
    )

    assert {a.device.ip for a in assessments} == {"10.0.0.5", "10.0.0.6"}
    # The OLED still updated for both devices despite the LEDs exploding.
    assert len(display.frames) == 2


def test_isolation_state_is_unchanged_by_the_leds(monkeypatch) -> None:
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH)})

    assessments, _reports = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        assessment_observer=run_pi_live._build_assessment_observer(
            _RecordingDisplay(), _RecordingIndicator()
        ),
    )

    assert assessments[0].isolation is not None
    assert assessments[0].isolation.enforced is False
