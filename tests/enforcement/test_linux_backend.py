"""Unit tests for enforcement.linux_backend — the Linux/Raspberry-Pi
backend location and its injected, mockable rule-construction and
command-execution seams (Phase 3A isolation backend contract).

Nothing here executes a firewall command. Every command runner used is a
test double; the backend's own default runner never spawns a process, and
its default rule builder refuses to construct a command at all.
"""
from __future__ import annotations

import ast
import inspect
import logging
from typing import List, Sequence

import pytest

from enforcement.backends import IsolationBackend, IsolationOutcome
from enforcement.command_runner import CommandResult, CommandRunner
from enforcement.linux_backend import (
    LINUX_BACKEND_NAME,
    IsolationPolicyNotFrozenError,
    LinuxIsolationBackend,
    unfrozen_rule_builder,
)


class _RecordingRunner(CommandRunner):
    """Records every argv handed to it and reports success, without ever
    spawning a process."""

    def __init__(self, exit_code: int = 0, stderr: str = "") -> None:
        self.commands: List[tuple] = []
        self._exit_code = exit_code
        self._stderr = stderr

    def run(self, command: Sequence[str]) -> CommandResult:
        self.commands.append(tuple(command))
        return CommandResult(
            command=tuple(command),
            executed=True,
            exit_code=self._exit_code,
            stderr=self._stderr,
        )


class _RaisingRunner(CommandRunner):
    def run(self, command: Sequence[str]) -> CommandResult:
        raise OSError("simulated runner explosion")


def _fake_rule_builder(device_identifier: str) -> Sequence[Sequence[str]]:
    """A deliberately fictitious rule, used only to prove the seam works.
    It is NOT a proposed CIPHER firewall policy — see the module
    docstring of enforcement/linux_backend.py."""
    return [["fake-firewall", "block", device_identifier]]


# --- the backend is a real IsolationBackend ---


def test_linux_backend_is_an_isolation_backend() -> None:
    assert isinstance(LinuxIsolationBackend(), IsolationBackend)


def test_linux_backend_returns_an_isolation_outcome() -> None:
    assert isinstance(LinuxIsolationBackend().isolate("10.0.0.5", 9), IsolationOutcome)


def test_linux_backend_names_itself_in_the_outcome() -> None:
    outcome = LinuxIsolationBackend().isolate("10.0.0.5", 9)
    assert outcome.backend == LINUX_BACKEND_NAME == "linux"


# --- default construction cannot enforce anything ---


def test_default_backend_requests_but_does_not_enforce() -> None:
    """Constructed with no arguments — on any platform — it must never
    claim a firewall change."""
    outcome = LinuxIsolationBackend().isolate("10.0.0.5", 9)
    assert (outcome.requested, outcome.enforced) == (True, False)


def test_default_backend_reason_names_the_unfrozen_policy() -> None:
    outcome = LinuxIsolationBackend().isolate("10.0.0.5", 9)
    assert "not frozen" in outcome.reason.lower()


def test_default_backend_does_not_raise(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="enforcement.linux_backend"):
        LinuxIsolationBackend().isolate("10.0.0.5", 9)
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_unfrozen_rule_builder_refuses_to_invent_a_rule() -> None:
    with pytest.raises(IsolationPolicyNotFrozenError):
        unfrozen_rule_builder("10.0.0.5")


# --- the injected seams work end to end ---


def test_injected_rule_builder_and_runner_enforce() -> None:
    runner = _RecordingRunner()
    backend = LinuxIsolationBackend(command_runner=runner, rule_builder=_fake_rule_builder)

    outcome = backend.isolate("10.0.0.5", 9)

    assert (outcome.requested, outcome.enforced) == (True, True)


def test_backend_passes_the_correct_device_identifier_to_the_rule_builder() -> None:
    runner = _RecordingRunner()
    backend = LinuxIsolationBackend(command_runner=runner, rule_builder=_fake_rule_builder)

    backend.isolate("10.0.0.5", 9)

    assert runner.commands == [("fake-firewall", "block", "10.0.0.5")]


def test_backend_preserves_device_identifier_and_risk_score_in_the_outcome() -> None:
    backend = LinuxIsolationBackend(
        command_runner=_RecordingRunner(), rule_builder=_fake_rule_builder
    )
    outcome = backend.isolate("10.0.0.5", 9)
    assert (outcome.device_ip, outcome.risk_score) == ("10.0.0.5", 9)


def test_every_command_in_a_multi_command_policy_is_run() -> None:
    runner = _RecordingRunner()
    backend = LinuxIsolationBackend(
        command_runner=runner,
        rule_builder=lambda ip: [["fake-a", ip], ["fake-b", ip]],
    )

    backend.isolate("10.0.0.5", 9)

    assert runner.commands == [("fake-a", "10.0.0.5"), ("fake-b", "10.0.0.5")]


# --- failures are surfaced, never raised ---


def test_nonzero_exit_code_is_reported_as_not_enforced() -> None:
    backend = LinuxIsolationBackend(
        command_runner=_RecordingRunner(exit_code=1, stderr="permission denied"),
        rule_builder=_fake_rule_builder,
    )

    outcome = backend.isolate("10.0.0.5", 9)

    assert outcome.enforced is False
    assert "permission denied" in outcome.reason


def test_a_raising_runner_is_reported_not_propagated() -> None:
    backend = LinuxIsolationBackend(
        command_runner=_RaisingRunner(), rule_builder=_fake_rule_builder
    )

    outcome = backend.isolate("10.0.0.5", 9)

    assert outcome.enforced is False
    assert "simulated runner explosion" in outcome.reason


def test_a_raising_rule_builder_is_reported_not_propagated() -> None:
    def boom(ip: str) -> Sequence[Sequence[str]]:
        raise ValueError("simulated policy error")

    outcome = LinuxIsolationBackend(rule_builder=boom).isolate("10.0.0.5", 9)

    assert outcome.enforced is False
    assert "simulated policy error" in outcome.reason


def test_an_empty_rule_builder_is_not_treated_as_success() -> None:
    outcome = LinuxIsolationBackend(rule_builder=lambda ip: []).isolate("10.0.0.5", 9)
    assert outcome.enforced is False


def test_a_second_command_failing_does_not_report_enforced() -> None:
    class _FailSecond(CommandRunner):
        def __init__(self) -> None:
            self.calls = 0

        def run(self, command: Sequence[str]) -> CommandResult:
            self.calls += 1
            return CommandResult(tuple(command), executed=True, exit_code=0 if self.calls == 1 else 2)

    outcome = LinuxIsolationBackend(
        command_runner=_FailSecond(),
        rule_builder=lambda ip: [["fake-a", ip], ["fake-b", ip]],
    ).isolate("10.0.0.5", 9)

    assert outcome.enforced is False


# --- restore seam ---


def test_restore_without_an_injected_builder_does_not_enforce() -> None:
    outcome = LinuxIsolationBackend().restore("10.0.0.5")
    assert (outcome.requested, outcome.enforced) == (True, False)
    assert "not supported" in outcome.reason.lower()


def test_restore_uses_its_own_injected_rule_builder() -> None:
    runner = _RecordingRunner()
    backend = LinuxIsolationBackend(
        command_runner=runner,
        rule_builder=_fake_rule_builder,
        restore_rule_builder=lambda ip: [["fake-firewall", "unblock", ip]],
    )

    outcome = backend.restore("10.0.0.5")

    assert outcome.enforced is True
    assert runner.commands == [("fake-firewall", "unblock", "10.0.0.5")]


# --- no firewall policy is invented, and no process can be spawned ---


def test_linux_backend_module_never_imports_subprocess_or_os() -> None:
    import enforcement.linux_backend as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "subprocess" not in imported
    assert "os" not in imported


def test_linux_backend_constructs_no_command_argv_of_its_own() -> None:
    """Guards the explicit Phase 3A instruction not to invent the network
    policy: this module must contain no argv literal at all. Every
    command comes from an injected RuleBuilder, so a string list that
    could be handed to a CommandRunner must not appear here — not even a
    placeholder one. (The deferred decisions are named in prose in the
    module docstring; prose is not argv.)"""
    import enforcement.linux_backend as module

    tree = ast.parse(inspect.getsource(module))
    argv_literals = [
        [elt.value for elt in node.elts]
        for node in ast.walk(tree)
        if isinstance(node, (ast.List, ast.Tuple))
        and node.elts
        and all(isinstance(elt, ast.Constant) and isinstance(elt.value, str) for elt in node.elts)
    ]

    assert argv_literals == []
