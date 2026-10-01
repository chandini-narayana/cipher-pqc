"""Unit tests for hardware.gpio_indicator — the optional three-LED GPIO
adapter, driven entirely through an injected fake lamp factory.

No real GPIO pin, no `gpiozero` installation, no Raspberry Pi and no
privilege is required. The fake lamps record every on/off/close call, which
proves the switching order, the one-lamp-at-a-time guarantee, the write
caching and every failure path without touching hardware.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pytest

from hardware.gpio_indicator import (
    MAX_BCM_PIN,
    MIN_BCM_PIN,
    GPIOStatusIndicator,
    GPIOUnavailableError,
    InvalidPinConfigurationError,
    validate_pins,
)
from hardware.indicator import LAMP_AMBER, LAMP_GREEN, LAMP_RED, StatusIndicator
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

# Arbitrary test pins. These are NOT a proposed CIPHER pin map - the real
# wiring is still pending and is always supplied by configuration.
GREEN_PIN, AMBER_PIN, RED_PIN = 17, 27, 22


class _FakeLamp:
    def __init__(self, pin: int, log: List[str]) -> None:
        self.pin = pin
        self.is_lit = False
        self.closed = False
        self._log = log

    def on(self) -> None:
        self.is_lit = True
        self._log.append(f"on:{self.pin}")

    def off(self) -> None:
        self.is_lit = False
        self._log.append(f"off:{self.pin}")

    def close(self) -> None:
        self.closed = True
        self._log.append(f"close:{self.pin}")


class _FakeGPIO:
    """Records every lamp built and every call made to it."""

    def __init__(self) -> None:
        self.calls: List[str] = []
        self.lamps: Dict[int, _FakeLamp] = {}

    def factory(self, pin: int) -> _FakeLamp:
        lamp = _FakeLamp(pin, self.calls)
        self.lamps[pin] = lamp
        return lamp

    def lit_pins(self) -> List[int]:
        return [pin for pin, lamp in self.lamps.items() if lamp.is_lit]


def _indicator(factory=None, **kwargs) -> GPIOStatusIndicator:
    pins = {"green_pin": GREEN_PIN, "amber_pin": AMBER_PIN, "red_pin": RED_PIN}
    pins.update(kwargs)
    return GPIOStatusIndicator(lamp_factory=factory or (lambda pin: _FakeLamp(pin, [])), **pins)


def _started(gpio: _FakeGPIO) -> GPIOStatusIndicator:
    indicator = _indicator(factory=gpio.factory)
    indicator.start()
    gpio.calls.clear()
    return indicator


def _assessment(category: RiskCategory) -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("192.168.50.21", TS),
        risk_assessment=RiskAssessment(9, category, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=category,
        assessed_at=TS,
    )


# --- Windows / no-library safety ------------------------------------------


def test_importing_this_module_needs_no_gpio_library() -> None:
    """The decisive Windows property: importing the adapter must not pull in
    a GPIO stack. Proven by this file having imported it, plus a static
    check that no GPIO import exists at module level."""
    import ast
    import inspect

    import hardware.gpio_indicator as module

    tree = ast.parse(inspect.getsource(module))
    module_level = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            module_level.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module_level.add(node.module.split(".")[0])

    for forbidden in ("gpiozero", "RPi", "lgpio", "pigpio", "board", "digitalio"):
        assert forbidden not in module_level


def test_the_driver_import_is_lazy_and_inside_a_function() -> None:
    import ast
    import inspect

    import hardware.gpio_indicator as module

    tree = ast.parse(inspect.getsource(module))
    gpio_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("gpiozero")
    ]
    assert gpio_imports, "expected the driver to be imported somewhere"

    top_level = set(tree.body)
    for node in gpio_imports:
        assert node not in top_level


def test_only_one_gpio_library_is_referenced() -> None:
    """No competing GPIO stack: gpiozero only. Checked structurally, since
    the docstring explains in prose why RPi.GPIO was rejected, and prose
    cannot drive a pin."""
    import ast
    import inspect

    import hardware.gpio_indicator as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    gpio_libraries = imported & {"gpiozero", "RPi", "lgpio", "pigpio", "digitalio", "board"}
    assert gpio_libraries == {"gpiozero"}


def test_constructing_the_indicator_acquires_nothing() -> None:
    acquired: List[int] = []
    indicator = _indicator(factory=lambda pin: acquired.append(pin))

    assert acquired == []
    assert indicator.available is False


def test_a_missing_gpio_library_is_reported_not_raised(caplog) -> None:
    def _no_library(pin):
        raise GPIOUnavailableError("the optional GPIO library is not installed")

    indicator = _indicator(factory=_no_library)

    with caplog.at_level(logging.WARNING, logger="hardware.gpio_indicator"):
        started = indicator.start()

    assert started is False
    assert indicator.available is False
    assert any("unavailable" in r.getMessage().lower() for r in caplog.records)


def test_no_pin_number_is_hardcoded_in_the_module() -> None:
    """The wiring is pending, so the module must contain no pin constant
    other than the BCM range bounds it validates against."""
    import ast
    import inspect

    import hardware.gpio_indicator as module

    tree = ast.parse(inspect.getsource(module))
    assigned = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] = node.value.value

    numeric = {name: value for name, value in assigned.items() if isinstance(value, int)}
    assert set(numeric) == {"MIN_BCM_PIN", "MAX_BCM_PIN"}


def test_the_pins_have_no_default_values() -> None:
    """A pin must always be passed in; nothing is ever assumed."""
    import inspect

    signature = inspect.signature(GPIOStatusIndicator.__init__)
    for name in ("green_pin", "amber_pin", "red_pin"):
        assert signature.parameters[name].default is inspect.Parameter.empty


# --- pin validation -------------------------------------------------------


def test_valid_pins_are_labelled_by_colour() -> None:
    assert validate_pins([GREEN_PIN, AMBER_PIN, RED_PIN]) == {
        "green": GREEN_PIN,
        "amber": AMBER_PIN,
        "red": RED_PIN,
    }


def test_duplicate_pins_are_rejected() -> None:
    with pytest.raises(InvalidPinConfigurationError) as excinfo:
        validate_pins([17, 17, 22])
    assert "distinct" in str(excinfo.value)


def test_all_three_pins_identical_is_rejected() -> None:
    with pytest.raises(InvalidPinConfigurationError):
        validate_pins([17, 17, 17])


@pytest.mark.parametrize("value", ["17", None, 1.5, True, [17]])
def test_a_non_integer_pin_is_rejected(value) -> None:
    with pytest.raises(InvalidPinConfigurationError):
        validate_pins([value, AMBER_PIN, RED_PIN])


@pytest.mark.parametrize("value", [-1, MAX_BCM_PIN + 1, 99])
def test_an_out_of_range_pin_is_rejected(value) -> None:
    with pytest.raises(InvalidPinConfigurationError) as excinfo:
        validate_pins([value, AMBER_PIN, RED_PIN])
    assert "BCM range" in str(excinfo.value)


def test_the_range_bounds_are_the_header_bounds() -> None:
    assert (MIN_BCM_PIN, MAX_BCM_PIN) == (0, 27)
    validate_pins([MIN_BCM_PIN, 1, MAX_BCM_PIN])  # must not raise


@pytest.mark.parametrize("pins", [[17], [17, 27], [17, 27, 22, 23]])
def test_the_wrong_number_of_pins_is_rejected(pins) -> None:
    with pytest.raises(InvalidPinConfigurationError):
        validate_pins(pins)


def test_an_invalid_configuration_is_rejected_at_construction() -> None:
    """An operator error is caught before anything is acquired or driven."""
    acquired: List[int] = []
    with pytest.raises(InvalidPinConfigurationError):
        GPIOStatusIndicator(
            green_pin=17, amber_pin=17, red_pin=22, lamp_factory=lambda pin: acquired.append(pin)
        )
    assert acquired == []


# --- contract -------------------------------------------------------------


def test_the_adapter_is_a_status_indicator() -> None:
    assert isinstance(_indicator(), StatusIndicator)
    assert _indicator().indicator_name == "gpio"


def test_the_configured_pins_are_exposed_for_logging() -> None:
    assert _indicator().pins == {"green": GREEN_PIN, "amber": AMBER_PIN, "red": RED_PIN}


# --- startup --------------------------------------------------------------


def test_a_successful_start_acquires_all_three_pins(caplog) -> None:
    gpio = _FakeGPIO()
    indicator = _indicator(factory=gpio.factory)

    with caplog.at_level(logging.INFO, logger="hardware.gpio_indicator"):
        assert indicator.start() is True

    assert sorted(gpio.lamps) == sorted([GREEN_PIN, AMBER_PIN, RED_PIN])
    assert indicator.available is True
    assert any("ready" in r.getMessage().lower() for r in caplog.records)


def test_startup_leaves_every_lamp_off() -> None:
    """A known state, not whatever the pins happened to hold."""
    gpio = _FakeGPIO()
    indicator = _indicator(factory=gpio.factory)

    indicator.start()

    assert gpio.lit_pins() == []
    assert indicator.current_lamp is None
    assert all(call.startswith("off:") for call in gpio.calls)


def test_show_ready_leaves_every_lamp_off() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)

    indicator.show_ready()

    assert gpio.lit_pins() == []


# --- risk states ----------------------------------------------------------


@pytest.mark.parametrize(
    ("category", "pin"),
    [
        (RiskCategory.LOW, GREEN_PIN),
        (RiskCategory.MEDIUM, AMBER_PIN),
        (RiskCategory.HIGH, RED_PIN),
    ],
)
def test_each_category_lights_its_own_lamp(category, pin) -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)

    indicator.show_assessment(_assessment(category))

    assert gpio.lit_pins() == [pin]


@pytest.mark.parametrize("category", list(RiskCategory))
def test_exactly_one_lamp_is_ever_lit(category) -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)

    indicator.show_assessment(_assessment(category))

    assert len(gpio.lit_pins()) == 1


def test_a_transition_switches_the_previous_lamp_off() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)

    indicator.show_assessment(_assessment(RiskCategory.LOW))
    indicator.show_assessment(_assessment(RiskCategory.HIGH))
    indicator.show_assessment(_assessment(RiskCategory.MEDIUM))

    assert gpio.lit_pins() == [AMBER_PIN]
    assert indicator.current_lamp == LAMP_AMBER


def test_no_intermediate_state_leaves_two_lamps_lit() -> None:
    """Off-before-on: the recorded call order never has a second `on`
    before the previous lamp's `off`."""
    gpio = _FakeGPIO()
    indicator = _started(gpio)

    indicator.show_assessment(_assessment(RiskCategory.LOW))
    gpio.calls.clear()
    indicator.show_assessment(_assessment(RiskCategory.HIGH))

    assert gpio.calls.index(f"off:{GREEN_PIN}") < gpio.calls.index(f"on:{RED_PIN}")


def test_showing_none_puts_every_lamp_out() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)
    indicator.show_assessment(_assessment(RiskCategory.HIGH))

    indicator.show_lamp(None)

    assert gpio.lit_pins() == []
    assert indicator.current_lamp is None


def test_an_unknown_lamp_name_is_ignored_with_a_warning(caplog) -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)
    indicator.show_assessment(_assessment(RiskCategory.HIGH))
    gpio.calls.clear()

    with caplog.at_level(logging.WARNING, logger="hardware.gpio_indicator"):
        indicator.show_lamp("purple")

    assert gpio.calls == []
    assert gpio.lit_pins() == [RED_PIN]
    assert any("unknown" in r.getMessage().lower() for r in caplog.records)


# --- caching: no pointless GPIO traffic ----------------------------------


def test_an_unchanged_state_issues_no_writes() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)
    indicator.show_assessment(_assessment(RiskCategory.HIGH))
    gpio.calls.clear()

    for _ in range(5):
        indicator.show_assessment(_assessment(RiskCategory.HIGH))

    assert gpio.calls == []


def test_a_repeated_off_state_issues_no_writes() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)  # start() already set the off state

    indicator.show_ready()
    indicator.show_ready()

    assert gpio.calls == []


def test_a_changed_state_does_issue_writes() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)

    indicator.show_assessment(_assessment(RiskCategory.LOW))

    assert gpio.calls != []


# --- failure handling -----------------------------------------------------


def test_an_initialization_failure_is_reported_not_raised(caplog) -> None:
    def _denied(pin):
        raise PermissionError("[Errno 13] Permission denied: '/dev/gpiochip0'")

    indicator = _indicator(factory=_denied)

    with caplog.at_level(logging.WARNING, logger="hardware.gpio_indicator"):
        started = indicator.start()

    assert started is False
    assert indicator.available is False
    assert any("GPIO" in r.getMessage() for r in caplog.records)


def test_a_partial_acquisition_releases_what_it_got() -> None:
    """If the third pin fails, the first two must not stay held."""
    gpio = _FakeGPIO()
    attempts = {"count": 0}

    def _fails_on_third(pin):
        attempts["count"] += 1
        if attempts["count"] == 3:
            raise OSError("GPIO busy")
        return gpio.factory(pin)

    indicator = _indicator(factory=_fails_on_third)

    assert indicator.start() is False
    assert all(lamp.closed for lamp in gpio.lamps.values())


def test_states_after_a_failed_start_are_silently_dropped() -> None:
    gpio = _FakeGPIO()

    def _denied(pin):
        raise PermissionError("Permission denied")

    indicator = _indicator(factory=_denied)
    indicator.start()

    indicator.show_assessment(_assessment(RiskCategory.HIGH))
    indicator.show_ready()
    indicator.close()

    assert gpio.calls == []


def test_nothing_is_driven_before_start() -> None:
    gpio = _FakeGPIO()
    indicator = _indicator(factory=gpio.factory)

    indicator.show_assessment(_assessment(RiskCategory.HIGH))

    assert gpio.calls == []


def test_a_write_failure_does_not_raise_and_disables_the_leds(caplog) -> None:
    class _FailingLamp(_FakeLamp):
        def on(self) -> None:
            raise OSError("[Errno 5] Input/output error")

    indicator = _indicator(factory=lambda pin: _FailingLamp(pin, []))
    indicator.start()

    with caplog.at_level(logging.WARNING, logger="hardware.gpio_indicator"):
        indicator.show_assessment(_assessment(RiskCategory.HIGH))

    assert indicator.available is False
    assert any("write failed" in r.getMessage().lower() for r in caplog.records)


def test_a_failing_indicator_stops_retrying_on_every_assessment() -> None:
    """One bad write disables output for the run, so a broken LED cannot
    cost a GPIO write per assessment."""
    attempts = {"count": 0}

    class _FailingLamp(_FakeLamp):
        def on(self) -> None:
            attempts["count"] += 1
            raise OSError("Input/output error")

    indicator = _indicator(factory=lambda pin: _FailingLamp(pin, []))
    indicator.start()

    for category in (RiskCategory.HIGH, RiskCategory.LOW, RiskCategory.MEDIUM):
        indicator.show_assessment(_assessment(category))

    assert attempts["count"] == 1


# --- shutdown and cleanup -------------------------------------------------


def test_close_puts_every_lamp_out_and_releases_the_pins() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)
    indicator.show_assessment(_assessment(RiskCategory.HIGH))

    indicator.close()

    assert gpio.lit_pins() == []
    assert all(lamp.closed for lamp in gpio.lamps.values())
    assert indicator.available is False
    assert indicator.current_lamp is None


def test_close_is_idempotent() -> None:
    gpio = _FakeGPIO()
    indicator = _started(gpio)

    indicator.close()
    closes = [call for call in gpio.calls if call.startswith("close:")]
    indicator.close()

    assert [call for call in gpio.calls if call.startswith("close:")] == closes


def test_close_is_safe_without_a_start() -> None:
    _indicator().close()


def test_close_survives_a_failing_switch_off() -> None:
    class _FailingOff(_FakeLamp):
        def off(self) -> None:
            raise OSError("Input/output error")

    indicator = _indicator(factory=lambda pin: _FailingOff(pin, []))
    indicator.start()

    indicator.close()  # must not raise

    assert indicator.available is False


def test_close_survives_a_failing_release() -> None:
    class _FailingClose(_FakeLamp):
        def close(self) -> None:
            raise OSError("could not release pin")

    indicator = _indicator(factory=lambda pin: _FailingClose(pin, []))
    indicator.start()

    indicator.close()  # must not raise

    assert indicator.available is False


def test_a_driver_without_close_is_tolerated() -> None:
    """Not every GPIO library needs an explicit release."""

    class _NoClose:
        def __init__(self, pin: int) -> None:
            self.pin = pin

        def on(self) -> None:
            return None

        def off(self) -> None:
            return None

    indicator = _indicator(factory=lambda pin: _NoClose(pin))
    indicator.start()

    indicator.close()  # must not raise


def test_no_global_gpio_reset_is_performed() -> None:
    """Only CIPHER's own pins are released; other processes' GPIO state is
    none of its business."""
    import inspect

    import hardware.gpio_indicator as module

    source = inspect.getsource(module)
    for forbidden in ("cleanup()", "GPIO.cleanup", "setmode", "setwarnings"):
        assert forbidden not in source


# --- no PWM, no blink codes ----------------------------------------------


def test_no_pwm_or_blink_behaviour_is_implemented() -> None:
    """Plain on/off lamps; no PWM, no blink codes, no boot animation."""
    import ast
    import inspect

    import hardware.gpio_indicator as module

    tree = ast.parse(inspect.getsource(module))
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            called.add(node.func.attr)

    for forbidden in ("blink", "pulse", "toggle", "sleep", "value"):
        assert forbidden not in called


def test_the_module_states_it_is_not_hardware_validated() -> None:
    """Honesty guard: the docstring must not be quietly changed to claim
    hardware validation that has not happened."""
    import hardware.gpio_indicator as module

    assert "NOT VALIDATED ON HARDWARE" in (module.__doc__ or "")
