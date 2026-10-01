"""Phase 3D tests for enforcement.subprocess_runner — the one CommandRunner
that really executes a command.

`subprocess.run` is stubbed in every test that would otherwise spawn
something, so nothing here runs iptables or touches this host's firewall.
Two tests do run a harmless, portable command (the Python interpreter
itself) to confirm the real execution path reports an exit status
correctly — no firewall utility and no privilege is involved.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

import enforcement.subprocess_runner as subprocess_runner
from enforcement.command_runner import CommandResult, CommandRunner
from enforcement.subprocess_runner import SubprocessCommandRunner


class _Completed:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _stub_run(monkeypatch, result=None, raises=None, recorder=None):
    def _fake_run(argv, **kwargs):
        if recorder is not None:
            recorder["argv"] = argv
            recorder["kwargs"] = kwargs
        if raises is not None:
            raise raises
        return result if result is not None else _Completed(0)

    monkeypatch.setattr(subprocess_runner.subprocess, "run", _fake_run)


def test_is_a_command_runner() -> None:
    assert isinstance(SubprocessCommandRunner(), CommandRunner)


# --- the shell is never involved -----------------------------------------


def test_shell_is_never_requested(monkeypatch) -> None:
    """The single most important property: no value is ever concatenated
    into a shell string, so a hostile IP cannot become a command."""
    recorder = {}
    _stub_run(monkeypatch, recorder=recorder)

    SubprocessCommandRunner().run(["iptables", "-w", "-L"])

    assert recorder["kwargs"].get("shell") in (None, False)


def test_the_command_is_passed_as_an_argument_list(monkeypatch) -> None:
    recorder = {}
    _stub_run(monkeypatch, recorder=recorder)

    SubprocessCommandRunner().run(["iptables", "-w", "-A", "CHAIN", "-s", "1.2.3.4"])

    assert recorder["argv"] == ["iptables", "-w", "-A", "CHAIN", "-s", "1.2.3.4"]


def test_a_value_containing_shell_metacharacters_stays_one_argument(monkeypatch) -> None:
    recorder = {}
    _stub_run(monkeypatch, recorder=recorder)

    SubprocessCommandRunner().run(["echo", "1.2.3.4; rm -rf /"])

    assert recorder["argv"][1] == "1.2.3.4; rm -rf /"


def test_the_module_never_passes_a_shell_keyword_at_all() -> None:
    """Checked structurally rather than textually: no call in this module
    passes `shell`, so the default (False) always applies. The docstring
    says "Never shell=True" in prose, and prose cannot spawn a shell."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(subprocess_runner))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                assert keyword.arg != "shell"

    # And no alternative spawning API is reached for either.
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            called.add(node.func.attr)
    for forbidden in ("system", "popen", "call", "check_call", "check_output", "Popen"):
        assert forbidden not in called


# --- result reporting -----------------------------------------------------


def test_a_successful_command_is_reported_as_executed_and_zero(monkeypatch) -> None:
    _stub_run(monkeypatch, _Completed(0, stdout="ok"))

    result = SubprocessCommandRunner().run(["iptables", "-w", "-L"])

    assert result.executed is True
    assert result.exit_code == 0
    assert result.succeeded is True
    assert result.stdout == "ok"


def test_a_non_zero_exit_is_reported_without_raising(monkeypatch) -> None:
    """iptables uses a non-zero exit for "rule not present", which the
    backend treats as normal flow — so this must never be an exception."""
    _stub_run(monkeypatch, _Completed(1, stderr="No chain/target/match by that name"))

    result = SubprocessCommandRunner().run(["iptables", "-w", "-C", "CHAIN"])

    assert result.executed is True
    assert result.exit_code == 1
    assert result.succeeded is False
    assert "No chain" in result.stderr


def test_the_command_is_echoed_back_in_the_result(monkeypatch) -> None:
    _stub_run(monkeypatch)
    result = SubprocessCommandRunner().run(["iptables", "-w", "-L"])
    assert result.command == ("iptables", "-w", "-L")


def test_non_string_arguments_are_coerced(monkeypatch) -> None:
    recorder = {}
    _stub_run(monkeypatch, recorder=recorder)

    SubprocessCommandRunner().run(["iptables", "-I", "FORWARD", 1])

    assert recorder["argv"] == ["iptables", "-I", "FORWARD", "1"]


def test_an_empty_command_is_refused_without_spawning(monkeypatch) -> None:
    def _must_not_run(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("an empty command must not be executed")

    monkeypatch.setattr(subprocess_runner.subprocess, "run", _must_not_run)

    result = SubprocessCommandRunner().run([])

    assert result.executed is False
    assert "empty command" in result.stderr


# --- failure modes, all reported rather than raised ----------------------


def test_a_missing_binary_is_reported_as_not_executed(monkeypatch) -> None:
    _stub_run(monkeypatch, raises=FileNotFoundError())

    result = SubprocessCommandRunner().run(["iptables", "-w", "-L"])

    assert result.executed is False
    assert result.succeeded is False
    assert "not found" in result.stderr


def test_a_permission_error_is_reported_as_not_executed(monkeypatch) -> None:
    _stub_run(monkeypatch, raises=PermissionError("Operation not permitted"))

    result = SubprocessCommandRunner().run(["iptables", "-w", "-L"])

    assert result.executed is False
    assert "not permitted" in result.stderr


def test_a_timeout_is_reported_not_raised(monkeypatch) -> None:
    _stub_run(monkeypatch, raises=subprocess.TimeoutExpired(cmd="iptables", timeout=10))

    result = SubprocessCommandRunner().run(["iptables", "-w", "-L"])

    assert result.executed is False
    assert "timed out" in result.stderr


def test_a_generic_os_error_is_reported_not_raised(monkeypatch) -> None:
    _stub_run(monkeypatch, raises=OSError("Exec format error"))

    result = SubprocessCommandRunner().run(["iptables", "-w", "-L"])

    assert result.executed is False
    assert "Exec format error" in result.stderr


def test_a_timeout_is_passed_to_subprocess(monkeypatch) -> None:
    recorder = {}
    _stub_run(monkeypatch, recorder=recorder)

    SubprocessCommandRunner(timeout=2.5).run(["iptables", "-w", "-L"])

    assert recorder["kwargs"]["timeout"] == 2.5


def test_output_is_captured_and_never_checked(monkeypatch) -> None:
    """check=False: a non-zero exit must come back as data, not as a
    CalledProcessError escaping into the pipeline."""
    recorder = {}
    _stub_run(monkeypatch, recorder=recorder)

    SubprocessCommandRunner().run(["iptables", "-w", "-L"])

    assert recorder["kwargs"]["capture_output"] is True
    assert recorder["kwargs"]["check"] is False


# --- the real execution path, with a harmless command --------------------


def test_the_real_path_reports_a_zero_exit() -> None:
    """Runs the Python interpreter, not a firewall utility: confirms the
    unstubbed path reports a real exit status."""
    result = SubprocessCommandRunner().run([sys.executable, "-c", "pass"])

    assert result.executed is True
    assert result.exit_code == 0


def test_the_real_path_reports_a_non_zero_exit() -> None:
    result = SubprocessCommandRunner().run([sys.executable, "-c", "raise SystemExit(3)"])

    assert result.executed is True
    assert result.exit_code == 3
    assert result.succeeded is False


def test_the_real_path_reports_a_genuinely_missing_binary() -> None:
    result = SubprocessCommandRunner().run(["cipher-no-such-binary-12345"])

    assert result.executed is False
    assert "not found" in result.stderr


# --- composition boundary -------------------------------------------------


def test_the_enforcement_package_does_not_re_export_this_runner() -> None:
    """Importing `enforcement` must not be enough to execute anything: a
    composition root has to reach for this module by name."""
    import enforcement

    assert not hasattr(enforcement, "SubprocessCommandRunner")


def test_the_enforcement_package_does_not_import_the_subprocess_runner() -> None:
    import ast
    import inspect

    import enforcement as package

    tree = ast.parse(inspect.getsource(package))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "subprocess_runner" not in node.module


def test_no_backend_defaults_to_this_runner() -> None:
    """Every backend's default runner is the non-executing one."""
    from enforcement.command_runner import UnavailableCommandRunner
    from enforcement.iptables_backend import IptablesIsolationBackend
    from enforcement.linux_backend import LinuxIsolationBackend

    for backend in (IptablesIsolationBackend(), LinuxIsolationBackend()):
        assert isinstance(backend._command_runner, UnavailableCommandRunner)
