"""Phase 3A isolation backend contract tests.

These tests pin the *contract* the pipeline depends on, end to end through
`pipeline.runner.run_capture()`, so that adding a real Linux enforcement
backend later cannot silently change CIPHER's behavior:

  * raw QRS >= threshold is the one and only isolation trigger
    (ML/fusion escalation alone never is),
  * the backend receives the correct device identifier,
  * `requested` and `enforced` stay two distinct facts, and the Windows
    NoOp backend reports requested=True / enforced=False,
  * a failing backend is surfaced, never fatal to the assessment
    pipeline,
  * no OS firewall command is executed anywhere along this path,
  * reports and the dashboard/API contract are unaffected by isolation.

The existing Phase 14 tests in tests/pipeline/test_runner.py and
tests/enforcement/test_decision.py remain the detailed per-unit coverage;
nothing here replaces them.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from typing import Iterator, List, Optional, Sequence, Tuple

import pytest

import pipeline.runner as runner_module
from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from enforcement import (
    IsolationBackend,
    IsolationOutcome,
    LinuxIsolationBackend,
    NoOpIsolationBackend,
)
from enforcement.command_runner import CommandResult, CommandRunner
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment
from pipeline.runner import run_capture

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_KEYS = (b"public-key-bytes", b"secret-key-bytes")
_HTTP_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


class _FakeCaptureSource(CaptureSource):
    def __init__(self, packets: List[RawPacket]) -> None:
        self._packets = packets

    def read_packets(self) -> Iterator[RawPacket]:
        yield from self._packets


def _raw_packet(src_ip: str) -> RawPacket:
    return RawPacket(
        src_ip=src_ip,
        dst_ip="192.168.1.1",
        src_port=51000,
        dst_port=80,
        payload=_HTTP_PAYLOAD,
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


class _RecordingBackend(IsolationBackend):
    """Captures the full IsolationOutcome it returns, plus every argument
    it was handed, without enforcing anything."""

    backend_name = "recording"

    def __init__(self) -> None:
        self.calls: List[Tuple[str, int]] = []

    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        self.calls.append((device_ip, risk_score))
        return IsolationOutcome(
            device_ip=device_ip,
            risk_score=risk_score,
            requested_at=TS,
            requested=True,
            enforced=False,
            reason="test double",
            backend=self.backend_name,
        )


@pytest.fixture(autouse=True)
def _no_real_report_generation(monkeypatch):
    monkeypatch.setattr(
        runner_module, "generate_report", lambda assessment, sk, pk, output_dir: (None, None)
    )


def _patch_assess(monkeypatch, assessment_by_ip):
    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return assessment_by_ip[device.ip]

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)


# --- 1. QRS < 7: no isolation request -------------------------------------


@pytest.mark.parametrize("risk_score", [0, 3, 6])
def test_raw_qrs_below_threshold_produces_no_isolation_request(monkeypatch, risk_score) -> None:
    category = RiskCategory.LOW if risk_score <= 2 else RiskCategory.MEDIUM
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", risk_score, category)})
    backend = _RecordingBackend()

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == []


# --- 2. QRS >= 7: isolation request occurs --------------------------------


@pytest.mark.parametrize("risk_score", [7, 8, 10])
def test_raw_qrs_at_or_above_threshold_produces_an_isolation_request(monkeypatch, risk_score) -> None:
    _patch_assess(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", risk_score, RiskCategory.HIGH)}
    )
    backend = _RecordingBackend()

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == [("10.0.0.5", risk_score)]


def test_the_production_default_threshold_is_still_seven() -> None:
    """The eligibility rule itself is unchanged by Phase 3A."""
    assert DEFAULT_RISK_ISOLATION_THRESHOLD == 7


# --- 3. ML escalation with raw QRS < 7: no isolation request --------------


def test_ml_escalation_alone_never_produces_an_isolation_request(monkeypatch) -> None:
    """A device fused up to HIGH purely because Isolation Forest flagged
    it, while its raw deterministic QRS is 5, must not be handed to any
    backend."""
    escalated = _assessment(
        "10.0.0.5",
        5,
        RiskCategory.MEDIUM,
        final_category=RiskCategory.HIGH,
        anomaly=AnomalyAssessment(is_anomaly=True, anomaly_score=-0.8, confidence=0.9),
    )
    _patch_assess(monkeypatch, {"10.0.0.5": escalated})
    backend = _RecordingBackend()

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == []


# --- 4. Windows/NoOp backend: requested=True, enforced=False --------------


def test_noop_backend_requests_without_enforcing() -> None:
    outcome = NoOpIsolationBackend().isolate("10.0.0.5", 9)
    assert (outcome.requested, outcome.enforced) == (True, False)


def test_noop_backend_identifies_itself_in_the_outcome() -> None:
    """`backend` is what lets an audit distinguish a deliberately
    non-enforcing deployment from a real one that failed."""
    assert NoOpIsolationBackend().isolate("10.0.0.5", 9).backend == "noop"


def test_noop_backend_restore_also_never_enforces() -> None:
    outcome = NoOpIsolationBackend().restore("10.0.0.5")
    assert (outcome.requested, outcome.enforced) == (True, False)


def test_windows_pipeline_run_uses_the_noop_backend_and_enforces_nothing(monkeypatch) -> None:
    """The full pipeline path with the Windows backend: the request is
    made, nothing is enforced, and the run completes normally."""
    outcomes: List[IsolationOutcome] = []
    real_backend = NoOpIsolationBackend()

    class _Observing(IsolationBackend):
        def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
            outcome = real_backend.isolate(device_ip, risk_score)
            outcomes.append(outcome)
            return outcome

    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH)})

    assessments, _ = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=_Observing()
    )

    assert len(outcomes) == 1
    assert outcomes[0].requested is True
    assert outcomes[0].enforced is False
    assert [a.device.ip for a in assessments] == ["10.0.0.5"]


# --- 5. backend failure is surfaced without crashing the pipeline ---------


def test_a_raising_backend_is_logged_and_the_pipeline_completes(monkeypatch, caplog) -> None:
    class _Raising(IsolationBackend):
        def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
            raise RuntimeError("simulated backend failure")

    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH)})

    with caplog.at_level("ERROR", logger="pipeline.runner"):
        assessments, _ = run_capture(
            _FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=_Raising()
        )

    assert [a.device.ip for a in assessments] == ["10.0.0.5"]
    assert any("10.0.0.5" in r.getMessage() for r in caplog.records if r.levelname == "ERROR")


def test_a_non_enforcing_outcome_is_logged_with_its_reason(monkeypatch, caplog) -> None:
    """An enforcement failure the backend reports (rather than raises) is
    still visible in the run log, with requested/enforced/reason."""

    class _Failing(IsolationBackend):
        def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
            return IsolationOutcome(
                device_ip=device_ip,
                risk_score=risk_score,
                requested_at=TS,
                requested=True,
                enforced=False,
                reason="simulated permission denied",
                backend="linux",
            )

    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH)})

    with caplog.at_level("INFO", logger="pipeline.runner"):
        run_capture(
            _FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=_Failing()
        )

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "simulated permission denied" in messages
    assert "enforced=False" in messages


# --- 6. the backend receives the correct device identifier ----------------


def test_backend_receives_the_src_ip_of_the_offending_device(monkeypatch) -> None:
    _patch_assess(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", 3, RiskCategory.MEDIUM),
            "10.0.0.9": _assessment("10.0.0.9", 9, RiskCategory.HIGH),
        },
    )
    backend = _RecordingBackend()

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5"), _raw_packet("10.0.0.9")]),
        None,
        *_KEYS,
        isolation_backend=backend,
    )

    assert backend.calls == [("10.0.0.9", 9)]


def test_the_linux_backend_rule_builder_receives_that_same_identifier(monkeypatch) -> None:
    """End to end: the identifier the pipeline derives reaches the Linux
    backend's injected rule construction unchanged."""
    seen: List[str] = []

    class _Runner(CommandRunner):
        def run(self, command: Sequence[str]) -> CommandResult:
            return CommandResult(tuple(command), executed=True, exit_code=0)

    def rule_builder(device_identifier: str) -> Sequence[Sequence[str]]:
        seen.append(device_identifier)
        return [["fake-firewall", device_identifier]]

    _patch_assess(monkeypatch, {"10.0.0.9": _assessment("10.0.0.9", 9, RiskCategory.HIGH)})

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.9")]),
        None,
        *_KEYS,
        isolation_backend=LinuxIsolationBackend(command_runner=_Runner(), rule_builder=rule_builder),
    )

    assert seen == ["10.0.0.9"]


# --- 7. no external firewall command is executed -------------------------


@pytest.fixture
def _forbid_process_spawning(monkeypatch):
    """Make any attempt to spawn a process during the test an immediate,
    loud failure — covering subprocess and the os.* spawn family."""

    def forbidden(*args, **kwargs):
        raise AssertionError(f"a process was spawned: {args!r}")

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, forbidden)
    for name in ("system", "popen", "execv", "spawnv"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, forbidden)


def test_noop_isolation_never_spawns_a_process(_forbid_process_spawning) -> None:
    NoOpIsolationBackend().isolate("10.0.0.5", 9)
    NoOpIsolationBackend().restore("10.0.0.5")


def test_a_full_high_risk_pipeline_run_never_spawns_a_process(
    monkeypatch, _forbid_process_spawning
) -> None:
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 10, RiskCategory.HIGH)})

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
    )


def test_a_default_linux_backend_never_spawns_a_process(_forbid_process_spawning) -> None:
    """Even an accidentally-constructed Linux backend cannot reach a
    firewall: its default rule builder and command runner both refuse."""
    outcome = LinuxIsolationBackend().isolate("10.0.0.5", 9)
    assert outcome.enforced is False


# --- 8. reports / API / dashboard remain compatible -----------------------


def test_isolation_outcome_is_not_part_of_any_persisted_or_serialized_model() -> None:
    """Isolation stays a runtime enforcement concern: no models/,
    reports/, or dashboard/ module imports enforcement, so the frozen
    report and REST contracts cannot have been changed by it."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    offenders = []
    for package in ("models", "reports", "dashboard"):
        for path in (root / package).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("enforcement"):
                    offenders.append(str(path))
                elif isinstance(node, ast.Import) and any(
                    alias.name.startswith("enforcement") for alias in node.names
                ):
                    offenders.append(str(path))

    assert offenders == []


def test_run_capture_return_shape_is_unchanged_by_isolation(monkeypatch) -> None:
    """A high-risk run still returns (assessments, reports) with one
    report per flagged device — enforcement is a side effect only."""
    _patch_assess(monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", 9, RiskCategory.HIGH)})
    monkeypatch.setattr(
        runner_module,
        "generate_report",
        lambda assessment, sk, pk, output_dir: ("/fake/report.pdf", "metadata"),
    )

    assessments, reports = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=_RecordingBackend(),
    )

    assert len(assessments) == 1
    assert reports == [("/fake/report.pdf", "metadata")]


def test_existing_positional_isolation_outcome_construction_still_works() -> None:
    """The new `backend` field is last and defaulted, so every existing
    caller and test double that builds an IsolationOutcome positionally
    keeps working untouched."""
    outcome = IsolationOutcome("10.0.0.5", 9, TS, True, False, "reason")
    assert outcome.backend == "unknown"
