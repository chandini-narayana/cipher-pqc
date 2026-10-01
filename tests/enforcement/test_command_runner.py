"""Unit tests for enforcement.command_runner — the injectable, mockable
execution seam (Phase 3A isolation backend contract).

No real process is ever spawned here: the only CommandRunner in this
phase, UnavailableCommandRunner, is defined never to spawn one, and a
static test below confirms the module has no process-spawning capability
at all.
"""
from __future__ import annotations

import ast
import inspect

import pytest

from enforcement.command_runner import CommandResult, CommandRunner, UnavailableCommandRunner


def test_command_runner_is_an_abstract_interface() -> None:
    with pytest.raises(TypeError):
        CommandRunner()  # abstract - cannot be instantiated directly


def test_unavailable_runner_reports_that_nothing_executed() -> None:
    result = UnavailableCommandRunner().run(["iptables", "-A", "FORWARD"])
    assert result.executed is False


def test_unavailable_runner_never_reports_success() -> None:
    result = UnavailableCommandRunner().run(["iptables", "-A", "FORWARD"])
    assert result.succeeded is False


def test_unavailable_runner_echoes_the_command_it_declined_to_run() -> None:
    """The declined argv is preserved so a test (or an audit log) can
    assert exactly what *would* have run."""
    result = UnavailableCommandRunner().run(["iptables", "-A", "FORWARD", "-s", "10.0.0.5"])
    assert result.command == ("iptables", "-A", "FORWARD", "-s", "10.0.0.5")


def test_unavailable_runner_explains_why_in_stderr() -> None:
    result = UnavailableCommandRunner().run(["nft", "list", "ruleset"])
    assert "unavailable" in result.stderr.lower()


def test_executed_zero_exit_is_the_only_success() -> None:
    assert CommandResult(("true",), executed=True, exit_code=0).succeeded is True
    assert CommandResult(("false",), executed=True, exit_code=1).succeeded is False
    # "exit code 0" from a command that never ran must never read as success.
    assert CommandResult(("true",), executed=False, exit_code=0).succeeded is False


def test_command_result_is_immutable() -> None:
    result = CommandResult(("true",), executed=True, exit_code=0)
    with pytest.raises(Exception):
        result.executed = False  # type: ignore[misc]


def test_command_runner_module_never_imports_subprocess_or_os() -> None:
    """Static confirmation that no process-spawning capability exists in
    this module — not merely that it wasn't called."""
    import enforcement.command_runner as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "subprocess" not in imported
    assert "os" not in imported
