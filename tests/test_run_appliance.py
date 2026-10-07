"""Tests for run_appliance.py — the appliance-mode composition root
(docs/SDD.md Phase A1 addendum).

`app.run()` is never called: Flask is stubbed at the module boundary, so no
socket is bound and no server thread is left behind. Capture, hardware and
enforcement are all stubbed or default to their safe no-op implementations,
so nothing here needs an interface, root, I2C, GPIO or a Raspberry Pi.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pytest

import run_appliance
from dashboard.state_store import ApplicationStateStore
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.report_metadata import ReportMetadata
from models.risk_assessment import RiskAssessment

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


class _RecordingDisplay:
    display_name = "recording"

    def __init__(self) -> None:
        self.started = False
        self.closed = False
        self.frames: List[list] = []

    def start(self) -> bool:
        self.started = True
        return True

    def show_ready(self, *args) -> None:
        self.frames.append(["ready", *args])

    def show_assessment(self, assessment) -> None:
        self.frames.append(["assessment", assessment.device.ip])

    def show_lines(self, lines) -> None:
        self.frames.append(list(lines))

    def close(self) -> None:
        self.closed = True


class _RecordingIndicator:
    indicator_name = "recording"

    def __init__(self) -> None:
        self.started = False
        self.closed = False
        self.lamps: List[Optional[str]] = []

    def start(self) -> bool:
        self.started = True
        return True

    def show_ready(self) -> None:
        self.lamps.append(None)

    def show_assessment(self, assessment) -> None:
        self.lamps.append(assessment.final_category.value)

    def show_lamp(self, lamp) -> None:
        self.lamps.append(lamp)

    def close(self) -> None:
        self.closed = True


class _FakeWorker:
    """Stands in for ApplianceCaptureWorker: records lifecycle without
    running any capture."""

    instances: List["_FakeWorker"] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.stop_event = threading.Event()
        self.started = False
        self.stopped = False
        self.joined = False
        self.cycles_completed = 0
        self.cycles_failed = 0
        _FakeWorker.instances.append(self)

    def stop(self) -> None:
        self.stopped = True
        self.stop_event.set()

    def start_thread(self):
        self.started = True
        worker = self

        # Simulate one cycle's per-packet observer call while the run is live,
        # so the observer wiring is exercised before shutdown closes the gate.
        observer = self.kwargs.get("capture_kwargs", {}).get("assessment_observer")
        if observer is not None:
            observer(_assessment("10.0.0.5"))

        class _FakeThread:
            daemon = True
            name = "cipher-appliance-capture"

            def join(self, timeout=None):
                worker.joined = True

            def is_alive(self):
                return False

        return _FakeThread()


@pytest.fixture
def stubbed(monkeypatch, tmp_path):
    """Stub every external dependency of main(), including app.run()."""
    _FakeWorker.instances.clear()
    recorded = {}

    display = _RecordingDisplay()
    indicator = _RecordingIndicator()

    class _FakeApp:
        def __init__(self) -> None:
            self.ran = False

        def run(self, **kwargs):
            self.ran = True
            recorded["run_kwargs"] = kwargs

    app = _FakeApp()

    def _create_app(state, settings):
        recorded["state"] = state
        recorded["settings"] = settings
        return app

    monkeypatch.setattr(run_appliance, "validate_web_build", lambda web_dir: recorded.setdefault("validated", web_dir))
    monkeypatch.setattr(run_appliance, "create_app", _create_app)
    monkeypatch.setattr(run_appliance, "register_spa", lambda a, web_dir: recorded.setdefault("spa", web_dir))
    monkeypatch.setattr(run_appliance, "load_anomaly_detector", lambda path: "detector")
    monkeypatch.setattr(run_appliance, "load_or_create_keypair", lambda path: (b"pk", b"sk"))
    monkeypatch.setattr(run_appliance, "configure_logging", lambda settings: None)
    monkeypatch.setattr(run_appliance, "_build_status_display", lambda mode: display)
    monkeypatch.setattr(run_appliance, "_build_status_indicator", lambda mode, pins: indicator)
    monkeypatch.setattr(run_appliance, "ApplianceCaptureWorker", _FakeWorker)
    monkeypatch.setattr(run_appliance, "_install_signal_handlers", lambda event: None)

    recorded["app"] = app
    recorded["display"] = display
    recorded["indicator"] = indicator
    return recorded


def _worker() -> _FakeWorker:
    assert _FakeWorker.instances, "expected a worker to be constructed"
    return _FakeWorker.instances[-1]


# --- interface and argument handling --------------------------------------


def test_no_interface_is_an_error(capsys) -> None:
    assert run_appliance.main([]) == 2
    assert "No interface specified" in capsys.readouterr().err


def test_the_interface_may_come_from_the_environment(stubbed, monkeypatch) -> None:
    monkeypatch.setenv("PI_CAPTURE_INTERFACE", "eth1")
    assert run_appliance.main([]) == 0


def test_the_default_cycle_is_five_seconds(stubbed) -> None:
    run_appliance.main(["--interface", "eth0"])
    assert _worker().kwargs["cycle_seconds"] == 5.0


def test_a_custom_cycle_is_honoured(stubbed) -> None:
    run_appliance.main(["--interface", "eth0", "--cycle-seconds", "12"])
    assert _worker().kwargs["cycle_seconds"] == 12.0


def test_a_sub_second_cycle_is_refused_with_an_explanation(stubbed, capsys) -> None:
    """A shorter cycle would reuse a device's whole-second report filename
    and overwrite its previous signed PDF."""
    assert run_appliance.main(["--interface", "eth0", "--cycle-seconds", "0.5"]) == 2
    assert "overwrite its previous signed report" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("flag", "value", "message"),
    [
        ("--enforcement", "nftables", "Unrecognized enforcement mode"),
        ("--display", "eink", "Unrecognized display mode"),
        ("--leds", "neopixel", "Unrecognized LED mode"),
    ],
)
def test_an_unrecognized_mode_from_the_environment_is_refused(
    stubbed, monkeypatch, capsys, flag, value, message
) -> None:
    env = {
        "--enforcement": "CIPHER_ENFORCEMENT",
        "--display": "CIPHER_DISPLAY",
        "--leds": "CIPHER_LEDS",
    }[flag]
    monkeypatch.setenv(env, value)

    assert run_appliance.main(["--interface", "eth0"]) == 2
    assert message in capsys.readouterr().err


def test_an_invalid_led_pin_configuration_exits_two(stubbed, monkeypatch, capsys) -> None:
    from hardware import InvalidPinConfigurationError

    def _raising(mode, pins):
        raise InvalidPinConfigurationError("the three GPIO pins must be distinct")

    monkeypatch.setattr(run_appliance, "_build_status_indicator", _raising)

    assert run_appliance.main(["--interface", "eth0", "--leds", "gpio"]) == 2
    assert "Invalid LED configuration" in capsys.readouterr().err


def test_an_invalid_led_configuration_still_closes_the_display(
    stubbed, monkeypatch
) -> None:
    """Issue 1 regression: the display is built before the indicator, so an
    invalid pin map must not abandon it."""
    from hardware import InvalidPinConfigurationError

    def _raising(mode, pins):
        raise InvalidPinConfigurationError("the three GPIO pins must be distinct")

    monkeypatch.setattr(run_appliance, "_build_status_indicator", _raising)

    run_appliance.main(["--interface", "eth0", "--leds", "gpio"])

    assert stubbed["display"].closed is True


def test_a_hostile_display_does_not_break_the_led_error_path(
    stubbed, monkeypatch, capsys
) -> None:
    """The cleanup on that path goes through _safe_display, so a panel that
    raises on close() must not turn a configuration error into a crash."""
    from hardware import InvalidPinConfigurationError

    class _HostileDisplay(_RecordingDisplay):
        def close(self) -> None:
            raise RuntimeError("panel exploded on close")

    monkeypatch.setattr(run_appliance, "_build_status_display", lambda mode: _HostileDisplay())
    monkeypatch.setattr(
        run_appliance,
        "_build_status_indicator",
        lambda mode, pins: (_ for _ in ()).throw(
            InvalidPinConfigurationError("pins must be distinct")
        ),
    )

    assert run_appliance.main(["--interface", "eth0", "--leds", "gpio"]) == 2
    assert "Invalid LED configuration" in capsys.readouterr().err


# --- safe defaults --------------------------------------------------------


def test_enforcement_defaults_to_noop(stubbed) -> None:
    """Real enforcement is never implicit, exactly as in run_pi_live."""
    from enforcement import NoOpIsolationBackend

    run_appliance.main(["--interface", "eth0"])

    backend = _worker().kwargs["capture_kwargs"]["isolation_backend"]
    assert isinstance(backend, NoOpIsolationBackend)


def test_the_display_and_leds_default_to_none(monkeypatch, stubbed) -> None:
    modes = {}

    def _record_display(mode):
        modes["display"] = mode
        return stubbed["display"]

    def _record_indicator(mode, pins):
        modes["leds"] = mode
        return stubbed["indicator"]

    monkeypatch.setattr(run_appliance, "_build_status_display", _record_display)
    monkeypatch.setattr(run_appliance, "_build_status_indicator", _record_indicator)

    run_appliance.main(["--interface", "eth0"])

    assert modes == {"display": "none", "leds": "none"}


def test_the_linux_guards_are_the_shared_ones_from_run_pi_live() -> None:
    """One implementation of the platform guards, not two: the appliance
    imports run_pi_live's builders rather than copying them."""
    import run_pi_live

    assert run_appliance._build_isolation_backend is run_pi_live._build_isolation_backend
    assert run_appliance._build_status_display is run_pi_live._build_status_display
    assert run_appliance._build_status_indicator is run_pi_live._build_status_indicator
    assert run_appliance._build_assessment_observer is run_pi_live._build_assessment_observer


def test_the_isolation_threshold_comes_from_settings(stubbed) -> None:
    from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD

    run_appliance.main(["--interface", "eth0"])

    kwargs = _worker().kwargs["capture_kwargs"]
    assert kwargs["risk_isolation_threshold"] == DEFAULT_RISK_ISOLATION_THRESHOLD


def test_the_real_pipeline_is_what_each_cycle_runs(stubbed) -> None:
    """No second assessment pipeline: the worker is handed run_capture
    itself."""
    from pipeline.runner import run_capture

    run_appliance.main(["--interface", "eth0"])

    assert _worker().kwargs["run_capture_fn"] is run_capture


# --- lifecycle ------------------------------------------------------------


def test_the_web_build_is_validated_before_capture_starts(monkeypatch, stubbed) -> None:
    """A missing build must fail in under a second, not after a cycle."""
    order = []
    monkeypatch.setattr(
        run_appliance, "validate_web_build", lambda web_dir: order.append("validate")
    )
    monkeypatch.setattr(
        run_appliance, "load_anomaly_detector", lambda path: order.append("model") or "detector"
    )

    original = _FakeWorker.start_thread

    def _tracking_start(self):
        order.append("worker")
        return original(self)

    monkeypatch.setattr(_FakeWorker, "start_thread", _tracking_start)

    run_appliance.main(["--interface", "eth0"])

    assert order.index("validate") < order.index("model") < order.index("worker")


def test_a_missing_web_build_aborts_before_any_capture(monkeypatch, stubbed, capsys) -> None:
    from dashboard.spa import MissingWebBuildError

    def _missing(web_dir):
        raise MissingWebBuildError("CIPHER web application is missing.")

    monkeypatch.setattr(run_appliance, "validate_web_build", _missing)

    assert run_appliance.main(["--interface", "eth0"]) == 1
    assert _FakeWorker.instances == []
    assert "missing" in capsys.readouterr().err


def test_the_dashboard_is_created_with_an_empty_store(stubbed) -> None:
    """Reachable immediately, before the first cycle has produced anything."""
    run_appliance.main(["--interface", "eth0"])

    store = stubbed["state"]
    assert isinstance(store, ApplicationStateStore)
    assert store.get().devices_assessed == 0


def test_the_spa_is_registered_on_the_app(stubbed) -> None:
    run_appliance.main(["--interface", "eth0"])
    assert stubbed["spa"] == run_appliance.WEB_DIR


def test_the_model_and_keys_are_loaded_once(monkeypatch, stubbed) -> None:
    loads = {"model": 0, "keys": 0}
    monkeypatch.setattr(
        run_appliance,
        "load_anomaly_detector",
        lambda path: loads.__setitem__("model", loads["model"] + 1) or "detector",
    )
    monkeypatch.setattr(
        run_appliance,
        "load_or_create_keypair",
        lambda path: loads.__setitem__("keys", loads["keys"] + 1) or (b"pk", b"sk"),
    )

    run_appliance.main(["--interface", "eth0"])

    assert loads == {"model": 1, "keys": 1}


def test_the_hardware_is_started_once_before_the_worker(stubbed) -> None:
    run_appliance.main(["--interface", "eth0"])

    assert stubbed["display"].started is True
    assert stubbed["indicator"].started is True


def test_the_server_runs_without_the_reloader(stubbed) -> None:
    """Werkzeug's reloader would spawn a second process with its own
    capture worker."""
    run_appliance.main(["--interface", "eth0"])

    kwargs = stubbed["run_kwargs"]
    assert kwargs["use_reloader"] is False
    assert kwargs["debug"] is False
    assert kwargs["threaded"] is True


def test_the_worker_is_started(stubbed) -> None:
    run_appliance.main(["--interface", "eth0"])
    assert _worker().started is True


# --- shutdown -------------------------------------------------------------


def test_shutdown_stops_and_joins_the_worker(stubbed) -> None:
    run_appliance.main(["--interface", "eth0"])

    worker = _worker()
    assert worker.stopped is True
    assert worker.joined is True


def test_shutdown_closes_the_display_and_the_indicator(stubbed) -> None:
    run_appliance.main(["--interface", "eth0"])

    assert stubbed["display"].closed is True
    assert stubbed["indicator"].closed is True


def test_a_keyboard_interrupt_still_shuts_down_cleanly(monkeypatch, stubbed) -> None:
    class _InterruptingApp:
        def run(self, **kwargs):
            raise KeyboardInterrupt

    monkeypatch.setattr(run_appliance, "create_app", lambda state, settings: _InterruptingApp())

    assert run_appliance.main(["--interface", "eth0"]) == 0
    assert _worker().stopped is True
    assert stubbed["display"].closed is True
    assert stubbed["indicator"].closed is True


def test_a_hostile_display_cannot_break_shutdown(monkeypatch, stubbed) -> None:
    class _HostileDisplay(_RecordingDisplay):
        def close(self) -> None:
            raise RuntimeError("panel exploded on close")

    monkeypatch.setattr(run_appliance, "_build_status_display", lambda mode: _HostileDisplay())

    assert run_appliance.main(["--interface", "eth0"]) == 0
    assert stubbed["indicator"].closed is True


def test_a_startup_failure_still_releases_the_hardware(monkeypatch, stubbed, capsys) -> None:
    from utils.exceptions import CipherError

    def _failing(path):
        raise CipherError("signing key directory is not writable")

    monkeypatch.setattr(run_appliance, "load_or_create_keypair", _failing)

    assert run_appliance.main(["--interface", "eth0"]) == 1
    assert stubbed["display"].closed is True
    assert stubbed["indicator"].closed is True


# --- capture source construction -----------------------------------------


def test_the_source_factory_builds_a_fresh_bounded_source_each_call(monkeypatch) -> None:
    built = []

    class _FakeSource:
        def __init__(self, **kwargs):
            built.append(kwargs)

    monkeypatch.setattr(run_appliance, "NetworkLiveCaptureSource", _FakeSource)
    factory = run_appliance._build_source_factory("eth0", 5.0, 1000, "ip")

    first = factory()
    second = factory()

    assert first is not second
    assert built[0] == {
        "interface": "eth0",
        "timeout": 5.0,
        "packet_limit": 1000,
        "bpf_filter": "ip",
    }
    assert built[0] == built[1]


def test_the_cycle_length_bounds_the_capture_source(monkeypatch, stubbed) -> None:
    """The cycle length IS the capture bound — there is no separate timer."""
    built = []

    class _FakeSource:
        def __init__(self, **kwargs):
            built.append(kwargs)

    monkeypatch.setattr(run_appliance, "NetworkLiveCaptureSource", _FakeSource)

    run_appliance.main(["--interface", "eth0", "--cycle-seconds", "7"])
    _worker().kwargs["source_factory"]()

    assert built[0]["timeout"] == 7.0


# --- the observer still drives the hardware per packet -------------------


def test_the_observer_passed_to_each_cycle_updates_both_devices(stubbed) -> None:
    """Hardware output stays per-packet and immediate: the worker receives an
    observer that fans out to the same display and LEDs run_pi_live uses.

    The fake worker calls it once while the run is live, so this covers the
    real wiring rather than a hand-built observer."""
    run_appliance.main(["--interface", "eth0"])

    assert ["assessment", "10.0.0.5"] in stubbed["display"].frames
    assert "HIGH" in stubbed["indicator"].lamps


def test_the_observer_is_inert_after_shutdown(stubbed) -> None:
    """Issue 2 regression: once shutdown has released the hardware, a worker
    that is somehow still running must not write to it."""
    run_appliance.main(["--interface", "eth0"])
    display = stubbed["display"]
    indicator = stubbed["indicator"]
    frames_at_shutdown = list(display.frames)
    lamps_at_shutdown = list(indicator.lamps)

    observer = _worker().kwargs["capture_kwargs"]["assessment_observer"]
    observer(_assessment("10.9.9.9"))

    assert display.frames == frames_at_shutdown
    assert indicator.lamps == lamps_at_shutdown


def test_hardware_output_is_disabled_before_any_device_is_released(stubbed) -> None:
    """Issue 2 regression, ordering: output must be disabled first, so a live
    worker stops writing before close() touches a device."""
    display = stubbed["display"]
    order = []

    class _OrderedDisplay(_RecordingDisplay):
        def close(self) -> None:
            order.append("close")
            super().close()

    ordered = _OrderedDisplay()
    stubbed["display"] = ordered

    import run_appliance as module

    original_gate = module.HardwareOutputGate

    class _TrackingGate(original_gate):
        def close(self):
            order.append("disable-output")
            return super().close()

    module.HardwareOutputGate = _TrackingGate
    module._build_status_display = lambda mode: ordered
    try:
        run_appliance.main(["--interface", "eth0"])
    finally:
        module.HardwareOutputGate = original_gate

    assert order.index("disable-output") < order.index("close")
    assert display is not ordered  # the ordered double really was used


def test_a_still_running_worker_does_not_block_hardware_release(stubbed) -> None:
    """A join that times out must not prevent release: disabling output first
    means there is at most one in-flight write to wait out."""

    class _NeverStoppingWorker(_FakeWorker):
        def start_thread(self):
            self.started = True
            worker = self

            class _LiveThread:
                daemon = True
                name = "cipher-appliance-capture"

                def join(self, timeout=None):
                    worker.joined = True

                def is_alive(self):
                    return True  # the join timed out

            return _LiveThread()

    import run_appliance as module

    module.ApplianceCaptureWorker = _NeverStoppingWorker
    try:
        assert run_appliance.main(["--interface", "eth0"]) == 0
    finally:
        module.ApplianceCaptureWorker = _FakeWorker

    assert stubbed["display"].closed is True
    assert stubbed["indicator"].closed is True


# --- the other entry points are untouched --------------------------------


def test_run_demo_is_not_imported_or_altered() -> None:
    """run_demo.py keeps its offline behaviour; the appliance does not reach
    into it."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(run_appliance))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert "run_demo" not in imported


def test_the_appliance_does_not_change_run_pi_live_behaviour(stubbed) -> None:
    """It imports run_pi_live's builders read-only; run_pi_live's own
    defaults must be unaffected."""
    import run_pi_live

    from enforcement import NoOpIsolationBackend
    from hardware import NoOpStatusDisplay, NoOpStatusIndicator

    run_appliance.main(["--interface", "eth0"])

    assert isinstance(run_pi_live._build_isolation_backend("noop"), NoOpIsolationBackend)
    assert isinstance(run_pi_live._build_status_display("none"), NoOpStatusDisplay)
    assert isinstance(run_pi_live._build_status_indicator("none", None), NoOpStatusIndicator)


# --- protected-device attribution (opt-in) --------------------------------


def test_no_protected_subnet_means_no_resolver(stubbed) -> None:
    """The opt-in default: run_capture keeps its historic src_ip identity."""
    run_appliance.main(["--interface", "eth0"])
    assert _worker().kwargs["capture_kwargs"]["device_resolver"] is None


def test_a_protected_subnet_installs_a_resolver(stubbed) -> None:
    run_appliance.main(["--interface", "eth0", "--protected-subnet", "192.168.50.0/24"])

    resolver = _worker().kwargs["capture_kwargs"]["device_resolver"]
    assert resolver is not None
    assert resolver("93.184.216.34", "192.168.50.24") == "192.168.50.24"
    assert resolver("192.168.50.24", "93.184.216.34") == "192.168.50.24"
    assert resolver("93.184.216.34", "8.8.8.8") is None


def test_several_protected_subnets_are_accepted(stubbed) -> None:
    run_appliance.main(
        ["--interface", "eth0", "--protected-subnet", "192.168.50.0/24,10.10.0.0/16"]
    )

    resolver = _worker().kwargs["capture_kwargs"]["device_resolver"]
    assert resolver("93.184.216.34", "10.10.4.5") == "10.10.4.5"


def test_the_protected_subnet_may_come_from_the_environment(stubbed, monkeypatch) -> None:
    monkeypatch.setenv("CIPHER_PROTECTED_SUBNETS", "192.168.50.0/24")

    run_appliance.main(["--interface", "eth0"])

    assert _worker().kwargs["capture_kwargs"]["device_resolver"] is not None


def test_an_explicit_subnet_flag_beats_the_environment(stubbed, monkeypatch) -> None:
    monkeypatch.setenv("CIPHER_PROTECTED_SUBNETS", "10.10.0.0/16")

    run_appliance.main(["--interface", "eth0", "--protected-subnet", "192.168.50.0/24"])

    resolver = _worker().kwargs["capture_kwargs"]["device_resolver"]
    assert resolver("93.184.216.34", "192.168.50.24") == "192.168.50.24"
    assert resolver("93.184.216.34", "10.10.4.5") is None


@pytest.mark.parametrize("value", ["nonsense", "192.168.50.0/33", "2001:db8::/32"])
def test_an_invalid_protected_subnet_exits_before_capture(stubbed, capsys, value) -> None:
    exit_code = run_appliance.main(["--interface", "eth0", "--protected-subnet", value])

    assert exit_code == 2
    assert "Invalid protected subnet" in capsys.readouterr().err
    assert _FakeWorker.instances == []


def test_the_appliances_own_address_is_excluded_from_the_scope(monkeypatch) -> None:
    """The Pi's address is inside the protected /24, so a plain membership test
    would make the appliance a protected device of itself."""
    monkeypatch.setattr(
        run_appliance, "local_ipv4_addresses", lambda: {"192.168.50.1"}
    )

    scope = run_appliance._build_protected_scope("192.168.50.0/24")

    assert scope.is_protected("192.168.50.1") is False
    assert scope.is_protected("192.168.50.24") is True
    assert scope.resolve("192.168.50.1", "93.184.216.34") is None


def test_self_discovery_failing_does_not_break_the_scope(monkeypatch) -> None:
    """Discovery is best-effort; an empty result means one fewer exclusion."""
    monkeypatch.setattr(run_appliance, "local_ipv4_addresses", lambda: set())

    scope = run_appliance._build_protected_scope("192.168.50.0/24")

    assert scope.is_protected("192.168.50.24") is True


def test_no_subnet_builds_no_scope() -> None:
    assert run_appliance._build_protected_scope(None) is None
    assert run_appliance._build_protected_scope("") is None


def test_the_banner_states_the_protected_scope(stubbed, capsys) -> None:
    run_appliance.main(["--interface", "eth0", "--protected-subnet", "192.168.50.0/24"])
    assert "192.168.50.0/24" in capsys.readouterr().out


def test_the_banner_states_when_no_scope_is_configured(stubbed, capsys) -> None:
    run_appliance.main(["--interface", "eth0"])
    assert "source-address identity" in capsys.readouterr().out


def test_no_subnet_is_hardcoded_in_application_logic() -> None:
    """The protected network is a deployment fact, like the interface name and
    the GPIO pins. It must appear only in help text and docstrings."""
    import ast
    import inspect

    import pipeline.device_resolution as resolution

    for module in (run_appliance, resolution):
        tree = ast.parse(inspect.getsource(module))
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                doc = ast.get_docstring(node, clean=False)
                if doc:
                    docstrings.add(doc)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in docstrings:
                    continue
                if "192.168.50" in node.value:
                    # Allowed only as an illustrative example in help text,
                    # never as a value the code would actually use.
                    lowered = node.value.lower()
                    assert "e.g." in lowered or "example" in lowered, node.value


# --- isolation threshold validation (pre-demo fix S2) ----------------------


@pytest.mark.parametrize("value", ["7", "8", "9", "10"])
def test_a_threshold_of_seven_or_more_is_allowed(stubbed, monkeypatch, value) -> None:
    monkeypatch.setenv("RISK_ISOLATION_THRESHOLD", value)

    assert run_appliance.main(["--interface", "eth0"]) == 0
    assert _worker().kwargs["capture_kwargs"]["risk_isolation_threshold"] == int(value)


@pytest.mark.parametrize("value", ["6", "3", "0", "-1"])
def test_a_threshold_below_seven_is_refused_not_clamped(stubbed, monkeypatch, capsys, value) -> None:
    monkeypatch.setenv("RISK_ISOLATION_THRESHOLD", value)

    exit_code = run_appliance.main(["--interface", "eth0", "--enforcement", "noop"])

    assert exit_code == 2
    err = capsys.readouterr().err
    assert f"configured isolation threshold is {value}" in err
    assert "7 is the minimum permitted physical-isolation threshold" in err
    assert _FakeWorker.instances == []  # nothing started, no capture


def test_the_minimum_threshold_is_the_project_default() -> None:
    from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD

    assert run_appliance.MIN_ISOLATION_THRESHOLD == DEFAULT_RISK_ISOLATION_THRESHOLD == 7


def test_the_banner_states_the_threshold(stubbed, capsys) -> None:
    run_appliance.main(["--interface", "eth0"])
    assert "raw QRS >= 7" in capsys.readouterr().out


# --- appliance self-exclusion (pre-demo fix M3) -----------------------------


def test_the_capture_interface_address_is_excluded_when_hostname_lookup_misses_it(
    stubbed, monkeypatch
) -> None:
    """Regression: on Debian the hostname resolves to 127.0.1.1 only, so the
    Pi's lab address used to stay protected and Pi->Windows packets were
    attributed to the Pi."""
    monkeypatch.setattr(run_appliance, "local_ipv4_addresses", lambda: {"127.0.1.1"})
    monkeypatch.setattr(run_appliance, "interface_ipv4_addresses", lambda name: {"192.168.50.1"})

    run_appliance.main(["--interface", "wlan1", "--protected-subnet", "192.168.50.0/24"])

    resolver = _worker().kwargs["capture_kwargs"]["device_resolver"]
    assert resolver("192.168.50.1", "192.168.50.24") == "192.168.50.24"
    assert resolver("192.168.50.24", "192.168.50.1") == "192.168.50.24"


def test_the_interface_addresses_are_read_for_the_named_interface(stubbed, monkeypatch) -> None:
    asked = []
    monkeypatch.setattr(
        run_appliance, "interface_ipv4_addresses", lambda name: asked.append(name) or set()
    )

    run_appliance.main(["--interface", "wlan1"])

    assert asked == ["wlan1"]


def test_an_enforcing_backend_is_wrapped_with_the_same_self_addresses(stubbed, monkeypatch) -> None:
    from appliance.interface_info import ApplianceSelfIsolationGuard
    from enforcement.command_runner import UnavailableCommandRunner
    from enforcement.iptables_backend import IptablesIsolationBackend

    monkeypatch.setattr(run_appliance, "local_ipv4_addresses", lambda: {"127.0.1.1"})
    monkeypatch.setattr(run_appliance, "interface_ipv4_addresses", lambda name: {"192.168.50.1"})
    monkeypatch.setattr(
        run_appliance,
        "_build_isolation_backend",
        lambda mode: IptablesIsolationBackend(command_runner=UnavailableCommandRunner()),
    )

    run_appliance.main(
        ["--interface", "wlan1", "--enforcement", "iptables", "--protected-subnet", "192.168.50.0/24"]
    )

    backend = _worker().kwargs["capture_kwargs"]["isolation_backend"]
    assert isinstance(backend, ApplianceSelfIsolationGuard)
    assert isinstance(backend.wrapped, IptablesIsolationBackend)
    assert backend.local_addresses == {"127.0.1.1", "192.168.50.1"}
    assert backend.isolate("192.168.50.1", 9).enforced is False
    assert "own addresses" in backend.isolate("192.168.50.1", 9).reason
    assert "not a protected device" in backend.isolate("93.184.216.34", 9).reason


# --- holding an enforced isolation on the outputs (pre-demo fix M5) ---------


def test_the_worker_holds_enforced_isolation_on_the_outputs_after_each_cycle(stubbed) -> None:
    run_appliance.main(["--interface", "eth0"])

    hook = _worker().kwargs["on_cycle_published"]
    assert callable(hook)


def test_the_worker_is_given_an_interface_identity_probe(stubbed, monkeypatch) -> None:
    monkeypatch.setattr(run_appliance, "interface_index", lambda name: 42 if name == "wlan1" else None)

    run_appliance.main(["--interface", "wlan1"])

    assert _worker().kwargs["interface_index_fn"]() == 42


# --- final pre-Pi patch: iptables requires a protected scope ---------------


def _iptables_without_firewall(monkeypatch) -> None:
    """Real IptablesIsolationBackend, but with a runner that executes nothing,
    so no firewall can be touched (and the Linux guard is bypassed on Windows)."""
    from enforcement.command_runner import UnavailableCommandRunner
    from enforcement.iptables_backend import IptablesIsolationBackend

    monkeypatch.setattr(
        run_appliance,
        "_build_isolation_backend",
        lambda mode: IptablesIsolationBackend(command_runner=UnavailableCommandRunner()),
    )


def test_noop_without_a_scope_still_starts(stubbed) -> None:
    from enforcement import NoOpIsolationBackend

    assert run_appliance.main(["--interface", "eth0", "--enforcement", "noop"]) == 0
    capture_kwargs = _worker().kwargs["capture_kwargs"]
    assert isinstance(capture_kwargs["isolation_backend"], NoOpIsolationBackend)
    assert capture_kwargs["device_resolver"] is None


def test_iptables_with_a_scope_starts(stubbed, monkeypatch) -> None:
    _iptables_without_firewall(monkeypatch)

    exit_code = run_appliance.main(
        ["--interface", "wlan1", "--enforcement", "iptables", "--protected-subnet", "192.168.50.0/24"]
    )

    assert exit_code == 0
    assert _worker().kwargs["capture_kwargs"]["device_resolver"] is not None


def test_iptables_with_a_scope_from_the_environment_starts(stubbed, monkeypatch) -> None:
    _iptables_without_firewall(monkeypatch)
    monkeypatch.setenv("CIPHER_PROTECTED_SUBNETS", "192.168.50.0/24")

    assert run_appliance.main(["--interface", "wlan1", "--enforcement", "iptables"]) == 0


def test_iptables_without_a_scope_is_refused(stubbed, monkeypatch, capsys) -> None:
    """Without a scope, identity falls back to src_ip, under which a remote
    server can become the isolation target. Real enforcement must refuse."""
    _iptables_without_firewall(monkeypatch)

    exit_code = run_appliance.main(["--interface", "wlan1", "--enforcement", "iptables"])

    assert exit_code == 2
    err = capsys.readouterr().err
    assert "physical iptables enforcement requires a protected subnet/scope" in err
    assert _FakeWorker.instances == []  # no capture, no worker
    assert stubbed["display"].started is False  # no hardware touched
    assert stubbed["indicator"].started is False


def test_iptables_from_the_environment_without_a_scope_is_refused(stubbed, monkeypatch, capsys) -> None:
    _iptables_without_firewall(monkeypatch)
    monkeypatch.setenv("CIPHER_ENFORCEMENT", "iptables")

    assert run_appliance.main(["--interface", "wlan1"]) == 2
    assert "requires a protected subnet/scope" in capsys.readouterr().err


def test_no_subnet_is_inferred_for_iptables(stubbed, monkeypatch) -> None:
    """Even with a discoverable interface address, no scope is invented."""
    _iptables_without_firewall(monkeypatch)
    monkeypatch.setattr(run_appliance, "interface_ipv4_addresses", lambda name: {"192.168.50.1"})

    assert run_appliance.main(["--interface", "wlan1", "--enforcement", "iptables"]) == 2


# --- final pre-Pi patch: threshold range 7..10 ------------------------------


@pytest.mark.parametrize("value", ["11", "12", "100"])
def test_a_threshold_above_ten_is_refused_not_clamped(stubbed, monkeypatch, capsys, value) -> None:
    """QRS is capped at 10, so a higher threshold would silently disable
    isolation."""
    monkeypatch.setenv("RISK_ISOLATION_THRESHOLD", value)

    assert run_appliance.main(["--interface", "eth0"]) == 2
    err = capsys.readouterr().err
    assert f"configured isolation threshold is {value}" in err
    assert "must be between 7 and 10" in err
    assert _FakeWorker.instances == []


@pytest.mark.parametrize("value,exit_code", [("6", 2), ("7", 0), ("8", 0), ("9", 0), ("10", 0), ("11", 2)])
def test_the_threshold_boundaries(stubbed, monkeypatch, value, exit_code) -> None:
    monkeypatch.setenv("RISK_ISOLATION_THRESHOLD", value)
    assert run_appliance.main(["--interface", "eth0"]) == exit_code


def test_the_default_threshold_is_unchanged_and_accepted(stubbed) -> None:
    assert run_appliance.main(["--interface", "eth0"]) == 0
    assert _worker().kwargs["capture_kwargs"]["risk_isolation_threshold"] == 7
    assert run_appliance.MAX_ISOLATION_THRESHOLD == 10


# --- final pre-Pi patch: the real main() M5 wiring --------------------------


def test_main_wires_an_enforced_isolation_into_a_held_oled_and_led(stubbed, monkeypatch) -> None:
    """Exercises the hook main() itself passes to the worker — not a copy of
    it — while the run is live, with the real frame and lamp mappings."""
    from dashboard.state import build_application_state
    from hardware.display import StatusDisplay
    from hardware.indicator import StatusIndicator

    class _Panel(StatusDisplay):
        display_name = "panel"

        def __init__(self) -> None:
            self.frames: List[list] = []

        def start(self) -> bool:
            return True

        def show_lines(self, lines) -> None:
            self.frames.append(list(lines))

        def close(self) -> None:
            pass

    class _Lamps(StatusIndicator):
        indicator_name = "lamps"

        def __init__(self) -> None:
            self.lit: List[Optional[str]] = []

        def start(self) -> bool:
            return True

        def show_lamp(self, lamp) -> None:
            self.lit.append(lamp)

        def close(self) -> None:
            pass

    panel, lamps = _Panel(), _Lamps()
    monkeypatch.setattr(run_appliance, "_build_status_display", lambda mode: panel)
    monkeypatch.setattr(run_appliance, "_build_status_indicator", lambda mode, pins: lamps)

    enforced = IsolationStatus(
        requested=True,
        enforced=True,
        backend="linux-iptables",
        reason="Isolated 192.168.50.24",
        requested_at=TS,
        enforcement_capable=True,
    )
    medium = DeviceAssessment(
        device=Device.first_contact("192.168.50.24", TS),
        risk_assessment=RiskAssessment(5, RiskCategory.MEDIUM, "r", "n"),
        anomaly_assessment=None,
        final_category=RiskCategory.MEDIUM,
        assessed_at=TS,
    )
    during_run = {}

    def _live_cycle(worker_self):
        # What the real worker does after publishing a cycle, using exactly
        # the hook and observer main() composed.
        state = build_application_state([_assessment("192.168.50.24", isolation=enforced)], [])
        worker_self.kwargs["on_cycle_published"](state)
        worker_self.kwargs["capture_kwargs"]["assessment_observer"](medium)
        during_run["frames"] = list(panel.frames)
        during_run["lamps"] = list(lamps.lit)

        class _Thread:
            daemon = True

            def join(self, timeout=None):
                pass

            def is_alive(self):
                return False

        return _Thread()

    monkeypatch.setattr(_FakeWorker, "start_thread", _live_cycle)

    assert run_appliance.main(["--interface", "eth0"]) == 0

    isolated_frame = ["CIPHER", "Device: 192.168.50.24", "QRS: 9/10", "Risk: HIGH", "Isolation: ISOLATED"]
    assert during_run["frames"][-1] == isolated_frame  # the MEDIUM frame never rendered
    assert during_run["lamps"] == [None, "red"]  # ready, then held red; no amber
