"""Unit tests for run_live_demo.py's composition — the temporary
host-level live-capture demo entry point.

Mirrors tests/test_run_demo.py's pattern: Flask.run is always patched
out so no test binds a real port, and scapy/Npcap/LiveCaptureSource are
always replaced with an in-memory fake — no test in this file requires
a real network interface or elevated privileges.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from flask import Flask

import run_demo
import run_live_demo
from capture.base import CaptureSource
from capture.host_live_source import InterfaceInfo
from capture.raw_packet import RawPacket
from enforcement import NoOpIsolationBackend
from models.enums import RiskCategory
from utils.exceptions import CaptureError


def _tls_like_packet(src_ip: str = "10.0.0.5") -> RawPacket:
    return RawPacket(
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        src_port=51000,
        dst_port=443,
        payload=b"\x16\x03\x03\x00\x10" + b"A" * 16,
        timestamp=datetime.now(timezone.utc),
    )


def _plaintext_http_packet(src_ip: str = "10.0.0.6") -> RawPacket:
    return RawPacket(
        src_ip=src_ip,
        dst_ip="10.0.0.1",
        src_port=51010,
        dst_port=80,
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        timestamp=datetime.now(timezone.utc),
    )


class _FakeLiveCaptureSource(CaptureSource):
    """Stands in for capture.host_live_source.LiveCaptureSource so
    these tests never touch scapy.sniff/Npcap. Records the constructor
    arguments it was called with for assertion."""

    last_instance = None

    def __init__(self, interface: str, timeout: float, packet_limit: int) -> None:
        self.interface = interface
        self.timeout = timeout
        self.packet_limit = packet_limit
        self.packets_captured = 0
        type(self).last_instance = self

    def read_packets(self):
        for packet in _FAKE_PACKETS:
            self.packets_captured += 1
            yield packet


_FAKE_PACKETS = [_tls_like_packet(), _plaintext_http_packet()]


def _fake_interfaces():
    return [InterfaceInfo(index=3, name="Wi-Fi", description="Test NIC", ipv4="10.0.0.5")]


@pytest.fixture(autouse=True)
def _stub_interfaces(monkeypatch):
    monkeypatch.setattr(run_live_demo, "list_interfaces", _fake_interfaces)

    def _fake_resolve(name: str):
        for info in _fake_interfaces():
            if info.name == name:
                return info
        raise CaptureError(f"Network interface {name!r} was not found.")

    monkeypatch.setattr(run_live_demo, "resolve_interface", _fake_resolve)


def _patch_flask_run(monkeypatch, captured: dict) -> None:
    def fake_run(self, host=None, port=None, **kwargs):
        captured["ran"] = True
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr(Flask, "run", fake_run)


# --- --list-interfaces -------------------------------------------------


def test_list_interfaces_prints_table_and_exits_zero(monkeypatch, capsys) -> None:
    def _forbidden(*args, **kwargs):
        raise AssertionError("nothing else should run for --list-interfaces")

    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _forbidden)

    exit_code = run_live_demo.main(["--list-interfaces"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Wi-Fi" in out
    assert "10.0.0.5" in out


# --- interface selection -------------------------------------------------


def test_no_interface_specified_fails_clearly(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LIVE_CAPTURE_INTERFACE", raising=False)

    def _forbidden(*args, **kwargs):
        raise AssertionError("LiveCaptureSource must not be constructed with no interface")

    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _forbidden)

    exit_code = run_live_demo.main([])

    assert exit_code == 1
    assert "No network interface specified" in capsys.readouterr().out


def test_invalid_interface_fails_clearly(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)

    def _forbidden(*args, **kwargs):
        raise AssertionError("LiveCaptureSource must not be constructed for an invalid interface")

    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _forbidden)

    exit_code = run_live_demo.main(["--interface", "NoSuchAdapter"])

    assert exit_code == 1
    assert "was not found" in capsys.readouterr().out


def test_live_capture_interface_env_var_used_when_no_cli_flag(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LIVE_CAPTURE_INTERFACE", "Wi-Fi")
    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _FakeLiveCaptureSource)

    captured = {}
    _patch_flask_run(monkeypatch, captured)

    exit_code = run_live_demo.main([])

    assert exit_code == 0
    assert _FakeLiveCaptureSource.last_instance.interface == "Wi-Fi"


def test_explicit_interface_flag_overrides_env_var(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LIVE_CAPTURE_INTERFACE", "SomethingElse")
    monkeypatch.setattr(
        run_live_demo,
        "resolve_interface",
        lambda name: InterfaceInfo(index=3, name=name, description="", ipv4=None),
    )
    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _FakeLiveCaptureSource)

    captured = {}
    _patch_flask_run(monkeypatch, captured)

    exit_code = run_live_demo.main(["--interface", "Wi-Fi"])

    assert exit_code == 0
    assert _FakeLiveCaptureSource.last_instance.interface == "Wi-Fi"


# --- web build ------------------------------------------------------------


def test_fails_fast_when_web_build_missing(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_live_demo, "WEB_DIR", tmp_path / "no_such_web_dir")

    def _forbidden(*args, **kwargs):
        raise AssertionError("LiveCaptureSource must not be constructed when the web build is missing")

    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _forbidden)

    exit_code = run_live_demo.main(["--interface", "Wi-Fi"])

    assert exit_code == 1
    assert "CIPHER web application is missing" in capsys.readouterr().out


# --- bounds propagation ----------------------------------------------------


def test_timeout_and_packet_limit_propagated_to_capture_source(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _FakeLiveCaptureSource)

    captured = {}
    _patch_flask_run(monkeypatch, captured)

    exit_code = run_live_demo.main(
        ["--interface", "Wi-Fi", "--timeout", "12.5", "--packet-limit", "99"]
    )

    assert exit_code == 0
    assert _FakeLiveCaptureSource.last_instance.timeout == 12.5
    assert _FakeLiveCaptureSource.last_instance.packet_limit == 99


# --- port ------------------------------------------------------------------


def test_defaults_to_port_5010(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _FakeLiveCaptureSource)

    captured = {}
    _patch_flask_run(monkeypatch, captured)

    exit_code = run_live_demo.main(["--interface", "Wi-Fi"])

    assert exit_code == 0
    assert captured["port"] == 5010


def test_port_override_is_respected(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _FakeLiveCaptureSource)

    captured = {}
    _patch_flask_run(monkeypatch, captured)

    exit_code = run_live_demo.main(["--interface", "Wi-Fi", "--port", "6123"])

    assert exit_code == 0
    assert captured["port"] == 6123
    assert "http://127.0.0.1:6123" in capsys.readouterr().out


# --- full run: same pipeline, NoOp enforcement, correct summary -----------


def test_full_run_uses_existing_pipeline_and_prints_summary(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _FakeLiveCaptureSource)

    captured = {}
    _patch_flask_run(monkeypatch, captured)

    real_run_capture = run_live_demo.run_capture
    backend_used = {}

    def spying_run_capture(capture_source, anomaly_detector, public_key, secret_key, isolation_backend, **kwargs):
        backend_used["backend"] = isolation_backend
        return real_run_capture(
            capture_source, anomaly_detector, public_key, secret_key, isolation_backend, **kwargs
        )

    monkeypatch.setattr(run_live_demo, "run_capture", spying_run_capture)

    exit_code = run_live_demo.main(["--interface", "Wi-Fi"])

    assert exit_code == 0
    assert isinstance(backend_used["backend"], NoOpIsolationBackend)

    out = capsys.readouterr().out
    assert "Packets captured: 2" in out
    assert "Devices assessed: 2" in out


def test_live_packets_use_the_same_assess_packet_path_as_offline(tmp_path, monkeypatch) -> None:
    """No special "live scoring" code: this exact payload must reach the
    same category assess_packet() gives it offline (verified directly
    against pipeline.assessment_pipeline.assess_packet)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_live_demo, "LiveCaptureSource", _FakeLiveCaptureSource)

    captured = {}
    _patch_flask_run(monkeypatch, captured)

    def fake_create_app(state, settings):
        captured["state"] = state
        return Flask("fake")

    monkeypatch.setattr(run_live_demo, "create_app", fake_create_app)

    exit_code = run_live_demo.main(["--interface", "Wi-Fi"])

    assert exit_code == 0
    assessment = captured["state"].get_assessment("10.0.0.5")
    assert assessment is not None
    assert assessment.final_category == RiskCategory.MEDIUM


# --- regression: the frozen offline application is untouched ---------------


def test_run_demo_module_has_no_coupling_to_the_live_demo() -> None:
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(run_demo))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert "run_live_demo" not in imported
    assert "capture.host_live_source" not in imported


def test_start_cipher_bat_does_not_reference_the_live_demo() -> None:
    bat_path = Path(__file__).resolve().parent.parent / "Start CIPHER.bat"
    content = bat_path.read_text()
    assert "run_live_demo" not in content
    assert "5010" not in content
