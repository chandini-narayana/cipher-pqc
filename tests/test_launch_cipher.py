"""Unit tests for launch_cipher.py — the Phase 15 presentation launcher
(docs/SDD.md's presentation-hardening addendum).

webbrowser.open is mocked in every test that could reach it — the
user's real browser must never open during a test run. Real subprocess
startup and real network calls are replaced with fakes; no test binds
a real port or starts a real run_demo.py process.
"""
from __future__ import annotations

import json
import time
import urllib.error

import pytest

import launch_cipher
import preflight

_ALL_PASS_RESULTS = [
    preflight.CheckResult("Python runtime", "PASS", "Python 3.12.0"),
    preflight.CheckResult("Required imports", "PASS", "ok"),
    preflight.CheckResult("Web UI", "PASS", "Ready"),
    preflight.CheckResult("Demo fixture", "PASS", "Ready"),
    preflight.CheckResult("Isolation Forest", "WARN", "Unavailable -- QRS-only mode"),
    preflight.CheckResult("Signing keys", "PASS", "Existing"),
    preflight.CheckResult(f"Port {preflight.DEFAULT_PORT}", "PASS", "Available"),
]

_BLOCKED_RESULTS = [
    preflight.CheckResult("Web UI", "FAIL", "CIPHER web application is missing."),
    *_ALL_PASS_RESULTS[1:],
]


class _FakeProcess:
    """A minimal stand-in for subprocess.Popen's return value.

    `exit_after_polls`, when set, makes poll() start returning
    `returncode` after that many calls -- simulating a process that
    exits partway through (either a real crash, or the observed
    scikit-learn/venv relaunch quirk launch_cipher.py must tolerate)."""

    def __init__(self, exit_after_polls: int | None = None, returncode: int = 0):
        self._polls = 0
        self._exit_after_polls = exit_after_polls
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self._wait_impl = lambda timeout=None: self.returncode

    def poll(self):
        self._polls += 1
        if self._exit_after_polls is not None and self._polls > self._exit_after_polls:
            return self.returncode
        return None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return self._wait_impl(timeout)


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = 200

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _never_healthy(url, timeout=1):
    raise urllib.error.URLError("connection refused")


def _healthy_after(n: int, payload: dict):
    calls = {"count": 0}

    def _fake_urlopen(url, timeout=1):
        calls["count"] += 1
        if calls["count"] < n:
            raise urllib.error.URLError("not up yet")
        return _FakeResponse(payload)

    _fake_urlopen.calls = calls
    return _fake_urlopen


# --- wait_until_ready --------------------------------------------------


def test_wait_until_ready_returns_health_once_available(monkeypatch) -> None:
    monkeypatch.setattr(launch_cipher.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        launch_cipher.urllib.request, "urlopen", _healthy_after(3, {"devices_assessed": 5, "reports_generated": 4})
    )

    process = _FakeProcess()
    health = launch_cipher.wait_until_ready(process, timeout_seconds=5)

    assert health == {"devices_assessed": 5, "reports_generated": 4}


def test_wait_until_ready_times_out_cleanly_without_hanging(monkeypatch) -> None:
    monkeypatch.setattr(launch_cipher.urllib.request, "urlopen", _never_healthy)
    monkeypatch.setattr(launch_cipher, "POLL_INTERVAL_SECONDS", 0.05)

    process = _FakeProcess()
    start = time.monotonic()
    health = launch_cipher.wait_until_ready(process, timeout_seconds=0.4)
    elapsed = time.monotonic() - start

    assert health is None
    assert elapsed < 2.0


def test_wait_until_ready_tolerates_early_process_exit_if_health_arrives_within_grace(
    monkeypatch,
) -> None:
    """The scikit-learn/venv relaunch quirk (see launch_cipher.py's
    module docstring): the tracked process can exit almost immediately
    while a relaunched, otherwise-healthy server keeps going. As long
    as health arrives within EXIT_GRACE_SECONDS of that exit, readiness
    must still be reported successfully."""
    monkeypatch.setattr(launch_cipher.time, "sleep", lambda s: None)
    monkeypatch.setattr(launch_cipher, "EXIT_GRACE_SECONDS", 10.0)
    monkeypatch.setattr(
        launch_cipher.urllib.request, "urlopen", _healthy_after(3, {"devices_assessed": 1, "reports_generated": 0})
    )

    process = _FakeProcess(exit_after_polls=0)  # "exited" from the first poll onward
    health = launch_cipher.wait_until_ready(process, timeout_seconds=5)

    assert health == {"devices_assessed": 1, "reports_generated": 0}


def test_wait_until_ready_gives_up_after_grace_period_when_process_exited_and_unhealthy(
    monkeypatch,
) -> None:
    monkeypatch.setattr(launch_cipher.urllib.request, "urlopen", _never_healthy)
    monkeypatch.setattr(launch_cipher, "EXIT_GRACE_SECONDS", 0.3)
    monkeypatch.setattr(launch_cipher, "POLL_INTERVAL_SECONDS", 0.05)

    process = _FakeProcess(exit_after_polls=0)
    start = time.monotonic()
    health = launch_cipher.wait_until_ready(process, timeout_seconds=10.0)
    elapsed = time.monotonic() - start

    assert health is None
    assert elapsed < 2.0  # bounded by the grace period, not the full 10s timeout


# --- run() ----------------------------------------------------------------


def test_run_does_not_start_subprocess_when_preflight_blocked(monkeypatch) -> None:
    def _forbidden(*args, **kwargs):
        raise AssertionError("subprocess.Popen must not be called when preflight is blocked")

    monkeypatch.setattr(launch_cipher.subprocess, "Popen", _forbidden)
    monkeypatch.setattr(launch_cipher.preflight, "run_preflight", lambda: _BLOCKED_RESULTS)

    assert launch_cipher.run() == 1


def test_run_opens_browser_only_after_health_is_ready(monkeypatch) -> None:
    fake_process = _FakeProcess(returncode=0)
    browser_calls = []

    monkeypatch.setattr(launch_cipher.subprocess, "Popen", lambda *a, **k: fake_process)
    monkeypatch.setattr(launch_cipher.preflight, "run_preflight", lambda: _ALL_PASS_RESULTS)
    monkeypatch.setattr(
        launch_cipher,
        "wait_until_ready",
        lambda process, timeout_seconds: {"devices_assessed": 5, "reports_generated": 4},
    )
    monkeypatch.setattr(launch_cipher.webbrowser, "open", lambda url: browser_calls.append(url))

    exit_code = launch_cipher.run(open_browser=True, timeout_seconds=5)

    assert exit_code == 0
    assert browser_calls == [launch_cipher.APP_URL]


def test_run_does_not_open_browser_when_not_ready(monkeypatch) -> None:
    fake_process = _FakeProcess()
    browser_calls = []

    monkeypatch.setattr(launch_cipher.subprocess, "Popen", lambda *a, **k: fake_process)
    monkeypatch.setattr(launch_cipher.preflight, "run_preflight", lambda: _ALL_PASS_RESULTS)
    monkeypatch.setattr(launch_cipher, "wait_until_ready", lambda process, timeout_seconds: None)
    monkeypatch.setattr(launch_cipher.webbrowser, "open", lambda url: browser_calls.append(url))

    exit_code = launch_cipher.run(open_browser=True, timeout_seconds=1)

    assert exit_code == 1
    assert browser_calls == []


def test_run_respects_no_browser_flag(monkeypatch) -> None:
    fake_process = _FakeProcess(returncode=0)
    browser_calls = []

    monkeypatch.setattr(launch_cipher.subprocess, "Popen", lambda *a, **k: fake_process)
    monkeypatch.setattr(launch_cipher.preflight, "run_preflight", lambda: _ALL_PASS_RESULTS)
    monkeypatch.setattr(
        launch_cipher, "wait_until_ready", lambda process, timeout_seconds: {"devices_assessed": 0, "reports_generated": 0}
    )
    monkeypatch.setattr(launch_cipher.webbrowser, "open", lambda url: browser_calls.append(url))

    launch_cipher.run(open_browser=False, timeout_seconds=5)

    assert browser_calls == []


def test_run_terminates_child_when_readiness_times_out(monkeypatch) -> None:
    fake_process = _FakeProcess()

    monkeypatch.setattr(launch_cipher.subprocess, "Popen", lambda *a, **k: fake_process)
    monkeypatch.setattr(launch_cipher.preflight, "run_preflight", lambda: _ALL_PASS_RESULTS)
    monkeypatch.setattr(launch_cipher, "wait_until_ready", lambda process, timeout_seconds: None)

    exit_code = launch_cipher.run(open_browser=False, timeout_seconds=1)

    assert exit_code == 1
    assert fake_process.terminated is True


def test_run_terminates_child_on_keyboard_interrupt(monkeypatch) -> None:
    fake_process = _FakeProcess(returncode=0)

    def _raise_interrupt(timeout=None):
        raise KeyboardInterrupt()

    fake_process._wait_impl = _raise_interrupt

    monkeypatch.setattr(launch_cipher.subprocess, "Popen", lambda *a, **k: fake_process)
    monkeypatch.setattr(launch_cipher.preflight, "run_preflight", lambda: _ALL_PASS_RESULTS)
    monkeypatch.setattr(
        launch_cipher, "wait_until_ready", lambda process, timeout_seconds: {"devices_assessed": 0, "reports_generated": 0}
    )
    monkeypatch.setattr(launch_cipher.webbrowser, "open", lambda url: None)

    exit_code = launch_cipher.run(open_browser=False, timeout_seconds=5)

    assert exit_code == 0
    assert fake_process.terminated is True


def test_terminate_falls_back_to_kill_if_terminate_does_not_stop_the_process() -> None:
    import subprocess

    class _StubbornProcess(_FakeProcess):
        def wait(self, timeout=None):
            if self.killed:
                return self.returncode
            if self.terminated:
                raise subprocess.TimeoutExpired(cmd="run_demo.py", timeout=timeout or 0)
            return self.returncode

    process = _StubbornProcess()
    launch_cipher._terminate(process)

    assert process.terminated is True
    assert process.killed is True


def test_terminate_is_a_noop_if_process_already_exited() -> None:
    process = _FakeProcess(exit_after_polls=0)
    process.poll()  # advance past the "exited" threshold
    launch_cipher._terminate(process)
    assert process.terminated is False


# --- main() / --check --------------------------------------------------


def test_main_check_flag_delegates_to_preflight(monkeypatch) -> None:
    called = {}

    def _fake_preflight_main():
        called["ran"] = True
        return 0

    monkeypatch.setattr(launch_cipher.preflight, "main", _fake_preflight_main)
    monkeypatch.setattr(launch_cipher.sys, "argv", ["launch_cipher.py", "--check"])

    assert launch_cipher.main() == 0
    assert called.get("ran") is True


def test_main_without_check_runs_the_full_launch(monkeypatch) -> None:
    called = {}

    def _fake_run(open_browser=True, timeout_seconds=30.0):
        called["open_browser"] = open_browser
        return 0

    monkeypatch.setattr(launch_cipher, "run", _fake_run)
    monkeypatch.setattr(launch_cipher.sys, "argv", ["launch_cipher.py"])

    assert launch_cipher.main() == 0
    assert called["open_browser"] is True


def test_main_no_browser_flag_is_passed_through(monkeypatch) -> None:
    called = {}

    def _fake_run(open_browser=True, timeout_seconds=30.0):
        called["open_browser"] = open_browser
        return 0

    monkeypatch.setattr(launch_cipher, "run", _fake_run)
    monkeypatch.setattr(launch_cipher.sys, "argv", ["launch_cipher.py", "--no-browser"])

    launch_cipher.main()
    assert called["open_browser"] is False
