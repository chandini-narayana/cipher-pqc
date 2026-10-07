"""Tests for appliance.interface_info — read-only interface facts and the
appliance-level guard against isolating the appliance itself (pre-demo fix
M3).

No real interface is touched: the ioctl is injected, sysfs is a tmp_path,
and the wrapped backend is the real IptablesIsolationBackend driving a fake
command runner that records every iptables invocation.
"""
from __future__ import annotations

import socket
from typing import List, Sequence

import pytest

from appliance.interface_info import (
    ApplianceSelfIsolationGuard,
    interface_index,
    interface_ipv4_addresses,
)
from enforcement.backends import NoOpIsolationBackend
from enforcement.command_runner import CommandResult, CommandRunner
from enforcement.iptables_backend import IptablesIsolationBackend
from pipeline.device_resolution import ProtectedScope

PI = "192.168.50.1"
WINDOWS = "192.168.50.24"
REMOTE = "93.184.216.34"


def _ioctl_returning(address: str):
    def _ioctl(fd, request, data):
        assert request == 0x8915  # SIOCGIFADDR, read-only
        return data[:20] + socket.inet_aton(address) + data[24:]

    return _ioctl


class _RecordingIptables(CommandRunner):
    """Every check reports 'absent' and every action succeeds."""

    def __init__(self) -> None:
        self.commands: List[tuple] = []

    def run(self, command: Sequence[str]) -> CommandResult:
        argv = tuple(command)
        self.commands.append(argv)
        exit_code = 1 if argv[2] in ("-L", "-C") else 0
        return CommandResult(command=argv, executed=True, exit_code=exit_code)


# --- interface_ipv4_addresses ---------------------------------------------


def test_the_interface_address_is_read_with_a_read_only_ioctl() -> None:
    assert interface_ipv4_addresses("wlan1", ioctl_fn=_ioctl_returning(PI)) == {PI}


def test_the_interface_name_is_passed_to_the_kernel() -> None:
    seen = {}

    def _ioctl(fd, request, data):
        seen["name"] = data[:16].rstrip(b"\x00")
        return data[:20] + socket.inet_aton(PI) + data[24:]

    interface_ipv4_addresses("wlan1", ioctl_fn=_ioctl)
    assert seen["name"] == b"wlan1"


def test_an_interface_without_an_address_yields_nothing() -> None:
    def _ioctl(fd, request, data):
        raise OSError(99, "Cannot assign requested address")

    assert interface_ipv4_addresses("wlan1", ioctl_fn=_ioctl) == set()


@pytest.mark.parametrize("name", [None, ""])
def test_no_interface_name_yields_nothing(name) -> None:
    assert interface_ipv4_addresses(name, ioctl_fn=_ioctl_returning(PI)) == set()


def test_a_platform_without_fcntl_yields_nothing(monkeypatch) -> None:
    import appliance.interface_info as module

    monkeypatch.setattr(module, "_default_ioctl", lambda: None)
    assert interface_ipv4_addresses("wlan1") == set()


# --- interface_index -------------------------------------------------------


def test_the_ifindex_is_read_from_sysfs(tmp_path) -> None:
    (tmp_path / "wlan1").mkdir()
    (tmp_path / "wlan1" / "ifindex").write_text("7\n")

    assert interface_index("wlan1", sys_class_net=tmp_path) == 7


def test_a_missing_interface_has_no_ifindex(tmp_path) -> None:
    assert interface_index("wlan1", sys_class_net=tmp_path) is None


# --- ApplianceSelfIsolationGuard -------------------------------------------


def _guarded(scope=None):
    runner = _RecordingIptables()
    backend = IptablesIsolationBackend(command_runner=runner, local_address_provider=lambda: {"127.0.1.1"})
    guard = ApplianceSelfIsolationGuard(
        backend, {"127.0.1.1", PI}, is_protected=scope.is_protected if scope else None
    )
    return guard, runner


def test_the_appliance_lab_address_is_refused_even_when_hostname_resolution_misses_it() -> None:
    """Regression: hostname resolution gave only 127.0.1.1, so the wrapped
    backend alone would have installed DROP rules for 192.168.50.1."""
    guard, runner = _guarded()

    outcome = guard.isolate(PI, 7)

    assert outcome.enforced is False
    assert "this host's own addresses" in outcome.reason
    assert runner.commands == []  # no iptables command at all


def test_a_protected_device_is_delegated_unchanged() -> None:
    guard, runner = _guarded(ProtectedScope(["192.168.50.0/24"], excluded_addresses=[PI]))

    outcome = guard.isolate(WINDOWS, 7)

    assert outcome.enforced is True
    assert any(WINDOWS in command for command in runner.commands)


def test_a_remote_address_is_refused_when_a_scope_is_configured() -> None:
    guard, runner = _guarded(ProtectedScope(["192.168.50.0/24"], excluded_addresses=[PI]))

    outcome = guard.isolate(REMOTE, 9)

    assert outcome.enforced is False
    assert "not a protected device" in outcome.reason
    assert runner.commands == []


@pytest.mark.parametrize("address", ["192.168.50.0", "192.168.50.255", "255.255.255.255"])
def test_network_and_broadcast_addresses_are_refused(address) -> None:
    guard, runner = _guarded(ProtectedScope(["192.168.50.0/24"], excluded_addresses=[PI]))

    assert guard.isolate(address, 9).enforced is False
    assert runner.commands == []


def test_the_guard_reports_the_wrapped_backend_identity() -> None:
    guard, _ = _guarded()
    assert guard.backend_name == "linux-iptables"
    assert guard.enforcement_capable is True
    assert guard.isolate(PI, 7).backend == "linux-iptables"


def test_restore_is_delegated_unchanged() -> None:
    guard, runner = _guarded()
    guard.restore(WINDOWS)
    assert any(WINDOWS in command for command in runner.commands)


def test_the_guard_never_decides_eligibility() -> None:
    """It only refuses targets. Whether isolate() is called at all is still
    should_isolate()'s raw-QRS decision, upstream in pipeline.runner."""
    import ast
    import inspect

    import appliance.interface_info as module

    tree = ast.parse(inspect.getsource(module))
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}

    assert "enforcement.decision" not in imported
    assert "should_isolate" not in names
    assert not attributes & {"final_category", "anomaly_assessment", "risk_assessment"}


def test_a_noop_backend_can_be_wrapped_without_gaining_enforcement() -> None:
    guard = ApplianceSelfIsolationGuard(NoOpIsolationBackend(), {PI})
    assert guard.isolate(WINDOWS, 9).enforced is False
    assert guard.enforcement_capable is False
