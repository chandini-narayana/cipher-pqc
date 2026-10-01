"""Phase 3D: the frozen eligibility rules, re-asserted end to end with the
REAL iptables backend wired into the pipeline.

Phase 3A/3B already proved these rules against test doubles. The point of
repeating them here is that a backend which actually issues firewall
commands is now reachable, so the consequence of a mistake changed: these
tests assert that nothing but raw QRS >= threshold can cause an iptables
command to be constructed, let alone run.

No real firewall is touched: the command runner is a recording fake, and a
fixture additionally makes any process spawn an immediate test failure.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from typing import Iterator, List, Optional, Sequence

import pytest

import pipeline.runner as runner_module
from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from enforcement.command_runner import CommandResult, CommandRunner
from enforcement.iptables_backend import CIPHER_CHAIN, IptablesIsolationBackend
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import ENFORCED
from models.risk_assessment import RiskAssessment
from pipeline.runner import run_capture

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_KEYS = (b"public-key-bytes", b"secret-key-bytes")
_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
_DEVICE = "192.168.50.21"


class _RecordingIptables(CommandRunner):
    """A fake iptables that succeeds at everything and records every argv.

    Checks report "absent" (exit 1) so the backend takes its full
    create/install/add path, giving the strongest possible signal if a
    command is ever issued when it should not be.
    """

    def __init__(self) -> None:
        self.commands: List[tuple] = []

    def run(self, command: Sequence[str]) -> CommandResult:
        argv = tuple(str(part) for part in command)
        self.commands.append(argv)
        exit_code = 1 if argv[2] in ("-L", "-C") else 0
        return CommandResult(command=argv, executed=True, exit_code=exit_code)


class _FakeCaptureSource(CaptureSource):
    def __init__(self, packets: List[RawPacket]) -> None:
        self._packets = packets

    def read_packets(self) -> Iterator[RawPacket]:
        yield from self._packets


def _raw_packet(src_ip: str = _DEVICE) -> RawPacket:
    return RawPacket(
        src_ip=src_ip,
        dst_ip="192.168.50.1",
        src_port=51000,
        dst_port=80,
        payload=_PAYLOAD,
        timestamp=TS,
    )


def _assessment(
    ip: str,
    risk_score: int,
    category: RiskCategory,
    final_category: Optional[RiskCategory] = None,
    anomaly: Optional[AnomalyAssessment] = None,
) -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(risk_score, category, "Some remediation text.", "NIST SP 800-52r2"),
        anomaly_assessment=anomaly,
        final_category=final_category or category,
        assessed_at=TS,
    )


@pytest.fixture(autouse=True)
def _no_reports_and_no_process_spawning(monkeypatch):
    monkeypatch.setattr(
        runner_module, "generate_report", lambda assessment, sk, pk, output_dir: (None, None)
    )

    def forbidden(*args, **kwargs):
        raise AssertionError(f"a process was spawned: {args!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    for name in ("system", "popen"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden)


def _patch_assess(monkeypatch, assessment_by_ip):
    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return assessment_by_ip[device.ip]

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)


def _run(monkeypatch, assessment, packets=None):
    _patch_assess(monkeypatch, {assessment.device.ip: assessment})
    runner = _RecordingIptables()
    backend = IptablesIsolationBackend(
        command_runner=runner, local_address_provider=lambda: {"192.168.50.1"}
    )
    assessments, _reports = run_capture(
        _FakeCaptureSource(packets or [_raw_packet(assessment.device.ip)]),
        None,
        *_KEYS,
        isolation_backend=backend,
    )
    return runner, assessments


# --- raw QRS is the only trigger -----------------------------------------


@pytest.mark.parametrize("risk_score", [0, 3, 6])
def test_below_the_threshold_no_iptables_command_is_ever_constructed(
    monkeypatch, risk_score
) -> None:
    category = RiskCategory.LOW if risk_score <= 2 else RiskCategory.MEDIUM
    runner, assessments = _run(monkeypatch, _assessment(_DEVICE, risk_score, category))

    assert runner.commands == []
    assert assessments[0].isolation is None


@pytest.mark.parametrize("risk_score", [7, 8, 10])
def test_at_or_above_the_threshold_the_device_is_really_isolated(monkeypatch, risk_score) -> None:
    runner, assessments = _run(monkeypatch, _assessment(_DEVICE, risk_score, RiskCategory.HIGH))

    assert ("iptables", "-w", "-A", CIPHER_CHAIN, "-s", _DEVICE, "-j", "DROP") in runner.commands
    assert assessments[0].isolation.enforced is True
    assert assessments[0].isolation.status_label == ENFORCED


def test_the_threshold_itself_is_unchanged() -> None:
    assert DEFAULT_RISK_ISOLATION_THRESHOLD == 7


def test_the_isolated_address_is_the_assessed_device(monkeypatch) -> None:
    """The identity that was assessed must be the identity that is
    enforced — no mismatch is acceptable."""
    runner, assessments = _run(monkeypatch, _assessment(_DEVICE, 9, RiskCategory.HIGH))

    isolated = {c[5] for c in runner.commands if c[2] == "-A"}
    assert isolated == {_DEVICE}
    assert assessments[0].device.ip == _DEVICE


# --- ML can never isolate -------------------------------------------------


def test_an_ml_escalated_high_category_cannot_isolate(monkeypatch) -> None:
    """Raw QRS 5, fused to HIGH purely because Isolation Forest flagged
    it: no iptables command may be constructed at all."""
    escalated = _assessment(
        _DEVICE,
        5,
        RiskCategory.MEDIUM,
        final_category=RiskCategory.HIGH,
        anomaly=AnomalyAssessment(anomaly_score=-0.9, is_anomaly=True, confidence=0.99),
    )
    runner, assessments = _run(monkeypatch, escalated)

    assert runner.commands == []
    assert assessments[0].final_category == RiskCategory.HIGH
    assert assessments[0].isolation is None


def test_a_strong_anomaly_score_alone_cannot_isolate(monkeypatch) -> None:
    low_with_anomaly = _assessment(
        _DEVICE,
        2,
        RiskCategory.LOW,
        final_category=RiskCategory.MEDIUM,
        anomaly=AnomalyAssessment(anomaly_score=-5.0, is_anomaly=True, confidence=1.0),
    )
    runner, _assessments = _run(monkeypatch, low_with_anomaly)

    assert runner.commands == []


def test_the_backend_never_sees_the_final_category_or_anomaly(monkeypatch) -> None:
    """Structural guarantee: isolate() receives only an IP and the raw
    score, so the backend cannot consult a fused or ML value even by
    accident."""
    import inspect

    signature = inspect.signature(IptablesIsolationBackend.isolate)
    assert list(signature.parameters) == ["self", "device_ip", "risk_score"]


def test_the_backend_module_references_no_fused_or_ml_identifier() -> None:
    """Checked structurally: no attribute, name or import in the module
    refers to a fused category or an ML result. (The module docstring
    names them in prose to record the rule; prose cannot read a score.)"""
    import ast
    import inspect

    import enforcement.iptables_backend as module

    tree = ast.parse(inspect.getsource(module))
    identifiers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.alias):
            identifiers.add(node.name.split(".")[-1])

    for forbidden in (
        "final_category",
        "anomaly_assessment",
        "AnomalyAssessment",
        "anomaly_score",
        "is_anomaly",
        "confidence",
        "fuse_assessments",
    ):
        assert forbidden not in identifiers


# --- enforcement failures do not break the pipeline ----------------------


def test_an_enforcement_failure_leaves_the_run_intact(monkeypatch) -> None:
    class _AllFail(CommandRunner):
        def run(self, command: Sequence[str]) -> CommandResult:
            return CommandResult(
                command=tuple(command),
                executed=False,
                exit_code=-1,
                stderr="'iptables' was not found on this system",
            )

    _patch_assess(monkeypatch, {_DEVICE: _assessment(_DEVICE, 9, RiskCategory.HIGH)})
    backend = IptablesIsolationBackend(
        command_runner=_AllFail(), local_address_provider=lambda: set()
    )

    assessments, _reports = run_capture(
        _FakeCaptureSource([_raw_packet()]), None, *_KEYS, isolation_backend=backend
    )

    assert [a.device.ip for a in assessments] == [_DEVICE]
    assert assessments[0].isolation.enforced is False
    assert "not found" in assessments[0].isolation.reason


def test_one_isolation_attempt_per_device_per_run(monkeypatch) -> None:
    """Phase 14's once-per-device rule still holds, so repeated high-risk
    packets cannot issue repeated firewall commands."""
    runner, _assessments = _run(
        monkeypatch,
        _assessment(_DEVICE, 9, RiskCategory.HIGH),
        packets=[_raw_packet(), _raw_packet(), _raw_packet()],
    )

    adds = [c for c in runner.commands if c[2] == "-A"]
    assert len(adds) == 2  # the -s and -d rules, issued exactly once
