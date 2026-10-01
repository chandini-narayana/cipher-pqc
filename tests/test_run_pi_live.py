"""Unit tests for run_pi_live.py — the Linux/Raspberry-Pi live-capture
composition root (docs/SDD.md Phase 3C addendum).

Nothing here captures a packet, opens an interface, or touches the
network: `run_capture` and the capture source are stubbed at the module
boundary, exactly as the other entry-point tests do.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import run_pi_live
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


class _FakeCounters:
    def summary(self) -> str:
        return "seen=3, yielded=2, skipped_non_ip=1, skipped_no_transport=0, parse_failures=0"


class _FakeSource:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.counters = _FakeCounters()


def _assessment(ip: str, score: int, isolation: IsolationStatus | None = None) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(score, RiskCategory.HIGH, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


@pytest.fixture
def stubbed(monkeypatch):
    """Stub every external dependency of main(): capture source, ML
    loading, signing keys, logging and run_capture. Records what the
    capture source was constructed with."""
    created = {}

    def _make_source(**kwargs):
        created.update(kwargs)
        return _FakeSource(**kwargs)

    calls = {}

    def _fake_run_capture(source, detector, public_key, secret_key, backend, **kwargs):
        calls["source"] = source
        calls["backend"] = backend
        calls["kwargs"] = kwargs
        return [_assessment("192.168.50.21", 9)], []

    monkeypatch.setattr(run_pi_live, "NetworkLiveCaptureSource", _make_source)
    monkeypatch.setattr(run_pi_live, "load_anomaly_detector", lambda path: None)
    monkeypatch.setattr(run_pi_live, "load_or_create_keypair", lambda path: (b"pk", b"sk"))
    monkeypatch.setattr(run_pi_live, "configure_logging", lambda settings: None)
    monkeypatch.setattr(run_pi_live, "run_capture", _fake_run_capture)
    return created, calls


# --- interface selection --------------------------------------------------


def test_no_interface_is_an_error_not_a_default(capsys) -> None:
    """The interface is never defaulted — a missing one must fail, so no
    management interface can be touched by accident."""
    exit_code = run_pi_live.main([])

    assert exit_code == 2
    assert "No interface specified" in capsys.readouterr().err


def test_the_explicit_interface_reaches_the_capture_source(stubbed) -> None:
    created, _calls = stubbed
    assert run_pi_live.main(["--interface", "eth0"]) == 0
    assert created["interface"] == "eth0"


def test_the_interface_may_come_from_the_environment(stubbed, monkeypatch) -> None:
    created, _calls = stubbed
    monkeypatch.setenv("PI_CAPTURE_INTERFACE", "eth1")

    assert run_pi_live.main([]) == 0
    assert created["interface"] == "eth1"


def test_an_explicit_flag_beats_the_environment(stubbed, monkeypatch) -> None:
    created, _calls = stubbed
    monkeypatch.setenv("PI_CAPTURE_INTERFACE", "eth1")

    run_pi_live.main(["--interface", "eth2"])
    assert created["interface"] == "eth2"


def test_timeout_and_packet_limit_are_passed_through(stubbed) -> None:
    created, _calls = stubbed
    run_pi_live.main(["--interface", "eth0", "--timeout", "12", "--packet-limit", "34"])

    assert created["timeout"] == 12.0
    assert created["packet_limit"] == 34


def test_a_bpf_filter_is_passed_through_when_given(stubbed) -> None:
    created, _calls = stubbed
    run_pi_live.main(["--interface", "eth0", "--filter", "ip"])
    assert created["bpf_filter"] == "ip"


def test_no_filter_is_applied_by_default(stubbed) -> None:
    created, _calls = stubbed
    run_pi_live.main(["--interface", "eth0"])
    assert created["bpf_filter"] is None


def test_no_interface_name_is_hardcoded_as_a_default() -> None:
    """--interface has no default, and no interface name appears as a
    default value anywhere in the parser."""
    args = run_pi_live._parse_args(["--list-interfaces"])
    assert args.interface is None


def test_list_interfaces_exits_without_capturing(monkeypatch, capsys) -> None:
    monkeypatch.setattr(run_pi_live, "available_interface_names", lambda: ["eth0", "lo"])

    def _must_not_run(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("capture must not start for --list-interfaces")

    monkeypatch.setattr(run_pi_live, "run_capture", _must_not_run)

    assert run_pi_live.main(["--list-interfaces"]) == 0
    assert "eth0" in capsys.readouterr().out


def test_list_interfaces_handles_an_empty_host(monkeypatch, capsys) -> None:
    monkeypatch.setattr(run_pi_live, "available_interface_names", lambda: [])
    assert run_pi_live.main(["--list-interfaces"]) == 0
    assert "none found" in capsys.readouterr().out


# --- enforcement policy is unchanged -------------------------------------


def test_the_noop_backend_is_used(stubbed) -> None:
    """Capture-only phase: this entry point must not enforce anything."""
    from enforcement import NoOpIsolationBackend

    _created, calls = stubbed
    run_pi_live.main(["--interface", "eth0"])

    assert isinstance(calls["backend"], NoOpIsolationBackend)


def test_the_isolation_threshold_comes_from_settings(stubbed) -> None:
    from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD

    _created, calls = stubbed
    run_pi_live.main(["--interface", "eth0"])

    assert calls["kwargs"]["risk_isolation_threshold"] == DEFAULT_RISK_ISOLATION_THRESHOLD


def test_no_nftables_or_other_firewall_technology_is_used() -> None:
    """Phase 3D froze iptables as the one enforcement technology. Nothing
    else may appear here (nor the generic, policy-free Linux seam, which
    this entry point deliberately does not compose)."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(run_pi_live))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(alias.name for alias in node.names)

    assert "LinuxIsolationBackend" not in imported
    source = inspect.getsource(run_pi_live).lower()
    for token in ("nftables", "firewalld", "ufw", "shell=true"):
        assert token not in source


# --- output ---------------------------------------------------------------


def test_the_disclaimer_states_that_nothing_is_enforced(stubbed, capsys) -> None:
    run_pi_live.main(["--interface", "eth0"])
    out = capsys.readouterr().out

    assert "capture only" in out.lower()
    assert "NONE" in out
    assert "never enforced" in out


def test_the_disclaimer_states_no_decryption(stubbed, capsys) -> None:
    run_pi_live.main(["--interface", "eth0"])
    out = capsys.readouterr().out
    assert "no WPA" in out
    assert "deauthentication" in out


def test_capture_counters_are_reported(stubbed, capsys) -> None:
    run_pi_live.main(["--interface", "eth0"])
    assert "seen=3, yielded=2" in capsys.readouterr().out


def test_each_device_is_listed_with_its_isolation_status(monkeypatch, stubbed, capsys) -> None:
    isolation = IsolationStatus(
        requested=True,
        enforced=False,
        backend="noop",
        reason="Hardware enforcement unavailable in current deployment",
        requested_at=TS,
        enforcement_capable=False,
    )

    def _fake_run_capture(*args, **kwargs):
        return [
            _assessment("192.168.50.21", 9, isolation),
            _assessment("192.168.50.22", 4),
        ], []

    monkeypatch.setattr(run_pi_live, "run_capture", _fake_run_capture)
    run_pi_live.main(["--interface", "eth0"])
    out = capsys.readouterr().out

    assert "192.168.50.21" in out
    assert "192.168.50.22" in out
    assert "Requested / not enforced" in out
    assert "Not requested" in out


def test_an_empty_capture_is_reported_clearly(monkeypatch, stubbed, capsys) -> None:
    monkeypatch.setattr(run_pi_live, "run_capture", lambda *a, **k: ([], []))
    assert run_pi_live.main(["--interface", "eth0"]) == 0
    assert "No IP-visible packets" in capsys.readouterr().out


# --- failure handling -----------------------------------------------------


def test_a_capture_error_exits_nonzero_without_a_traceback(monkeypatch, stubbed, capsys) -> None:
    from utils.exceptions import CaptureError

    def _raising(**kwargs):
        raise CaptureError("interface 'eth0' was not found")

    monkeypatch.setattr(run_pi_live, "NetworkLiveCaptureSource", _raising)

    assert run_pi_live.main(["--interface", "eth0"]) == 1
    assert "Live capture failed" in capsys.readouterr().err


def test_keyboard_interrupt_exits_cleanly(monkeypatch, stubbed) -> None:
    def _interrupting(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(run_pi_live, "run_capture", _interrupting)

    assert run_pi_live.main(["--interface", "eth0"]) == 130


# --- Phase 3D: explicit enforcement selection ----------------------------


def test_enforcement_defaults_to_noop(stubbed) -> None:
    """Real enforcement is never implicit: with no flag and no env var,
    the non-enforcing backend is used."""
    from enforcement import NoOpIsolationBackend

    _created, calls = stubbed
    run_pi_live.main(["--interface", "eth0"])

    assert isinstance(calls["backend"], NoOpIsolationBackend)


def test_explicit_noop_is_accepted(stubbed) -> None:
    from enforcement import NoOpIsolationBackend

    _created, calls = stubbed
    assert run_pi_live.main(["--interface", "eth0", "--enforcement", "noop"]) == 0
    assert isinstance(calls["backend"], NoOpIsolationBackend)


def test_iptables_enforcement_is_refused_off_linux(monkeypatch, stubbed, capsys) -> None:
    """The guard that keeps Windows runs and Windows tests away from a
    firewall even if the flag is passed."""
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Windows")

    exit_code = run_pi_live.main(["--interface", "eth0", "--enforcement", "iptables"])

    assert exit_code == 1
    assert "requires Linux" in capsys.readouterr().err


def test_iptables_enforcement_composes_the_iptables_backend_on_linux(
    monkeypatch, stubbed
) -> None:
    from enforcement import IptablesIsolationBackend

    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")
    _created, calls = stubbed

    assert run_pi_live.main(["--interface", "eth0", "--enforcement", "iptables"]) == 0
    assert isinstance(calls["backend"], IptablesIsolationBackend)


def test_the_iptables_backend_is_given_an_executing_runner(monkeypatch, stubbed) -> None:
    """This entry point is the only place that composes a runner capable
    of spawning a process."""
    from enforcement.subprocess_runner import SubprocessCommandRunner

    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")
    _created, calls = stubbed

    run_pi_live.main(["--interface", "eth0", "--enforcement", "iptables"])

    assert isinstance(calls["backend"]._command_runner, SubprocessCommandRunner)


def test_enforcement_may_come_from_the_environment(monkeypatch, stubbed) -> None:
    from enforcement import IptablesIsolationBackend

    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")
    monkeypatch.setenv("CIPHER_ENFORCEMENT", "iptables")
    _created, calls = stubbed

    run_pi_live.main(["--interface", "eth0"])

    assert isinstance(calls["backend"], IptablesIsolationBackend)


def test_an_explicit_flag_beats_the_enforcement_environment(monkeypatch, stubbed) -> None:
    from enforcement import NoOpIsolationBackend

    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")
    monkeypatch.setenv("CIPHER_ENFORCEMENT", "iptables")
    _created, calls = stubbed

    run_pi_live.main(["--interface", "eth0", "--enforcement", "noop"])

    assert isinstance(calls["backend"], NoOpIsolationBackend)


def test_an_unrecognized_enforcement_mode_is_refused(monkeypatch, stubbed, capsys) -> None:
    monkeypatch.setenv("CIPHER_ENFORCEMENT", "nftables")

    assert run_pi_live.main(["--interface", "eth0"]) == 2
    assert "Unrecognized enforcement mode" in capsys.readouterr().err


def test_the_disclaimer_warns_when_real_enforcement_is_active(
    monkeypatch, stubbed, capsys
) -> None:
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    run_pi_live.main(["--interface", "eth0", "--enforcement", "iptables"])
    out = capsys.readouterr().out

    assert "IPTABLES" in out
    assert "CIPHER_ISOLATION" in out
    assert "never flushes" in out


def test_the_disclaimer_states_the_forwarding_limitation(monkeypatch, stubbed, capsys) -> None:
    """Honest about what a monitor-only topology can and cannot do."""
    monkeypatch.setattr(run_pi_live.platform, "system", lambda: "Linux")

    run_pi_live.main(["--interface", "eth0", "--enforcement", "iptables"])

    assert "traverses this host" in capsys.readouterr().out


def test_no_firewall_command_is_executed_during_a_noop_run(monkeypatch, stubbed) -> None:
    """The Windows/default path must not reach a process spawn at all."""
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError(f"a process was spawned: {args!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)

    assert run_pi_live.main(["--interface", "eth0"]) == 0
