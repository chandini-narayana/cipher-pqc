"""Phase 3B tests for isolation-state propagation through
pipeline.runner.run_capture() (docs/SDD.md Phase 3B addendum).

These cover how an isolation attempt becomes visible on the returned
DeviceAssessment — the single seam by which enforcement state reaches the
REST API, the dashboard and the signed report. The Phase 14/3A tests in
tests/pipeline/test_runner.py and tests/enforcement/ remain the coverage
for *whether* and *when* the backend is called; nothing here replaces
them.

No real firewall command is executed: the only backends used are
NoOpIsolationBackend, test doubles, and LinuxIsolationBackend with an
injected non-spawning command runner.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Optional, Sequence

import pytest

import pipeline.runner as runner_module
from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from enforcement import IsolationBackend, IsolationOutcome, LinuxIsolationBackend, NoOpIsolationBackend
from enforcement.command_runner import CommandResult, CommandRunner
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import ENFORCED, FAILED, REQUESTED_NOT_ENFORCED
from models.risk_assessment import RiskAssessment
from pipeline.runner import run_capture

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_KEYS = (b"public-key-bytes", b"secret-key-bytes")
_HTTP_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
_IP = "10.0.0.5"


class _FakeCaptureSource(CaptureSource):
    def __init__(self, packets: List[RawPacket]) -> None:
        self._packets = packets

    def read_packets(self) -> Iterator[RawPacket]:
        yield from self._packets


def _raw_packet(src_ip: str = _IP) -> RawPacket:
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
    assessed_at: datetime = TS,
    anomaly: Optional[AnomalyAssessment] = None,
) -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(risk_score, category, "Some remediation text.", "NIST SP 800-52r2"),
        anomaly_assessment=anomaly,
        final_category=final_category or category,
        assessed_at=assessed_at,
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


def _patch_assess_sequence(monkeypatch, assessments: List[DeviceAssessment]):
    """Return a different assessment per packet, in order."""
    remaining = list(assessments)

    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return remaining.pop(0)

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)


def _run(backend: IsolationBackend) -> List[DeviceAssessment]:
    assessments, _ = run_capture(
        _FakeCaptureSource([_raw_packet()]), None, *_KEYS, isolation_backend=backend
    )
    return assessments


# --- 1. QRS < 7: no isolation state --------------------------------------


@pytest.mark.parametrize("risk_score", [0, 3, 6])
def test_below_threshold_leaves_isolation_absent(monkeypatch, risk_score) -> None:
    category = RiskCategory.LOW if risk_score <= 2 else RiskCategory.MEDIUM
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, risk_score, category)})

    assert _run(NoOpIsolationBackend())[0].isolation is None


# --- 2. QRS >= 7 with NoOp ------------------------------------------------


def test_at_threshold_with_noop_records_requested_not_enforced(monkeypatch) -> None:
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 7, RiskCategory.HIGH)})

    isolation = _run(NoOpIsolationBackend())[0].isolation

    assert isolation is not None
    assert isolation.requested is True
    assert isolation.enforced is False
    assert isolation.backend == "noop"
    assert isolation.reason
    assert isolation.requested_at is not None


def test_noop_state_is_labelled_requested_not_enforced(monkeypatch) -> None:
    """Windows must never present as physically isolated."""
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})

    isolation = _run(NoOpIsolationBackend())[0].isolation

    assert isolation.status_label == REQUESTED_NOT_ENFORCED
    assert isolation.enforcement_capable is False


# --- 3. a mock Linux success ----------------------------------------------


class _NonSpawningRunner(CommandRunner):
    """Reports success without ever spawning a process."""

    def __init__(self) -> None:
        self.commands: List[tuple] = []

    def run(self, command: Sequence[str]) -> CommandResult:
        self.commands.append(tuple(command))
        return CommandResult(tuple(command), executed=True, exit_code=0)


def test_a_successful_linux_backend_records_enforced(monkeypatch) -> None:
    """The future-hardware path: a real backend that succeeds must show
    enforced=True, labelled Enforced, naming the linux backend."""
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})
    command_runner = _NonSpawningRunner()
    backend = LinuxIsolationBackend(
        command_runner=command_runner,
        rule_builder=lambda ip: [["fake-firewall", "block", ip]],
    )

    isolation = _run(backend)[0].isolation

    assert isolation.requested is True
    assert isolation.enforced is True
    assert isolation.backend == "linux"
    assert isolation.enforcement_capable is True
    assert isolation.status_label == ENFORCED
    assert command_runner.commands == [("fake-firewall", "block", _IP)]


# --- 4. a backend-reported failure ---------------------------------------


def test_a_reported_backend_failure_is_recorded_as_failed(monkeypatch) -> None:
    """A real backend that could not enforce reads as Failed — not as a
    non-enforcing deployment — and the assessment survives."""
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})

    class _FailingRunner(CommandRunner):
        def run(self, command: Sequence[str]) -> CommandResult:
            return CommandResult(tuple(command), executed=True, exit_code=1, stderr="permission denied")

    assessments = _run(
        LinuxIsolationBackend(
            command_runner=_FailingRunner(), rule_builder=lambda ip: [["fake-firewall", ip]]
        )
    )

    assert [a.device.ip for a in assessments] == [_IP]
    isolation = assessments[0].isolation
    assert isolation.requested is True
    assert isolation.enforced is False
    assert isolation.status_label == FAILED
    assert "permission denied" in isolation.reason


def test_an_unfrozen_linux_policy_is_recorded_as_failed(monkeypatch) -> None:
    """A default-constructed Linux backend has no frozen rule: requested,
    not enforced, reason naming the unfrozen policy."""
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})

    isolation = _run(LinuxIsolationBackend())[0].isolation

    assert isolation.enforced is False
    assert "not frozen" in isolation.reason.lower()


# --- 5. a raising backend -------------------------------------------------


class _RaisingBackend(IsolationBackend):
    backend_name = "raising"
    enforcement_capable = True

    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        raise RuntimeError("simulated backend explosion")


def test_a_raising_backend_never_fabricates_enforced_true(monkeypatch) -> None:
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})

    assessments = _run(_RaisingBackend())

    assert [a.device.ip for a in assessments] == [_IP]
    assert assessments[0].isolation.enforced is False


def test_a_raising_backend_records_the_exception_as_the_reason(monkeypatch) -> None:
    """The attempt genuinely happened, so it is recorded as requested and
    failed — with the exception text as the auditable reason."""
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})

    isolation = _run(_RaisingBackend())[0].isolation

    assert isolation.requested is True
    assert isolation.status_label == FAILED
    assert "simulated backend explosion" in isolation.reason


# --- 9. ML escalation alone ----------------------------------------------


def test_ml_escalated_high_with_low_raw_qrs_has_no_isolation_state(monkeypatch) -> None:
    escalated = _assessment(
        _IP,
        5,
        RiskCategory.MEDIUM,
        final_category=RiskCategory.HIGH,
        anomaly=AnomalyAssessment(anomaly_score=-0.8, is_anomaly=True, confidence=0.9),
    )
    _patch_assess(monkeypatch, {_IP: escalated})

    assessments = _run(NoOpIsolationBackend())

    assert assessments[0].final_category == RiskCategory.HIGH
    assert assessments[0].isolation is None


# --- 10. once-per-device enforcement ------------------------------------


def test_many_high_risk_packets_still_record_one_attempt(monkeypatch) -> None:
    calls: List[str] = []

    class _Counting(IsolationBackend):
        backend_name = "counting"

        def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
            calls.append(device_ip)
            return IsolationOutcome(device_ip, risk_score, TS, True, False, "counted", "counting")

    _patch_assess_sequence(
        monkeypatch,
        [_assessment(_IP, 9, RiskCategory.HIGH, assessed_at=TS + timedelta(seconds=i)) for i in range(4)],
    )

    assessments, _ = run_capture(
        _FakeCaptureSource([_raw_packet() for _ in range(4)]),
        None,
        *_KEYS,
        isolation_backend=_Counting(),
    )

    assert calls == [_IP]
    assert assessments[0].isolation is not None


# --- 11. representative selection must not lose an enforcement event -----


def test_a_later_representative_does_not_erase_a_recorded_isolation(monkeypatch) -> None:
    """The regression this design exists to prevent.

    Both packets are HIGH with QRS 9, so `_is_stronger` breaks the tie on
    the later `assessed_at` — the second packet replaces the first as the
    representative. The first packet is the one that triggered isolation.
    If isolation were attached to that single assessment, the record would
    be silently lost here.
    """
    first = _assessment(_IP, 9, RiskCategory.HIGH, assessed_at=TS)
    second = _assessment(_IP, 9, RiskCategory.HIGH, assessed_at=TS + timedelta(seconds=30))
    _patch_assess_sequence(monkeypatch, [first, second])

    assessments, _ = run_capture(
        _FakeCaptureSource([_raw_packet(), _raw_packet()]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
    )

    # The later assessment did win representative selection ...
    assert assessments[0].assessed_at == TS + timedelta(seconds=30)
    # ... and the isolation event recorded on the earlier one survived.
    assert assessments[0].isolation is not None
    assert assessments[0].isolation.requested is True


def test_a_stronger_later_packet_also_keeps_the_isolation(monkeypatch) -> None:
    """Same rule when the later packet wins on category/score rather than
    on the timestamp tiebreak."""
    first = _assessment(_IP, 7, RiskCategory.HIGH, assessed_at=TS)
    second = _assessment(_IP, 10, RiskCategory.HIGH, assessed_at=TS + timedelta(seconds=5))
    _patch_assess_sequence(monkeypatch, [first, second])

    assessments, _ = run_capture(
        _FakeCaptureSource([_raw_packet(), _raw_packet()]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
    )

    assert assessments[0].risk_assessment.risk_score == 10
    assert assessments[0].isolation is not None


def test_isolation_is_recorded_when_a_later_packet_first_becomes_eligible(monkeypatch) -> None:
    """A device that starts MEDIUM and later turns HIGH: the escalation
    packet triggers enforcement and the state lands on the representative."""
    first = _assessment(_IP, 5, RiskCategory.MEDIUM, assessed_at=TS)
    second = _assessment(_IP, 9, RiskCategory.HIGH, assessed_at=TS + timedelta(seconds=5))
    _patch_assess_sequence(monkeypatch, [first, second])

    assessments, _ = run_capture(
        _FakeCaptureSource([_raw_packet(), _raw_packet()]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
    )

    assert assessments[0].isolation is not None
    assert assessments[0].final_category == RiskCategory.HIGH


def test_only_the_isolated_device_gains_isolation_state(monkeypatch) -> None:
    _patch_assess(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", 4, RiskCategory.MEDIUM),
            "10.0.0.9": _assessment("10.0.0.9", 9, RiskCategory.HIGH),
        },
    )

    assessments, _ = run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5"), _raw_packet("10.0.0.9")]),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
    )

    by_ip = {a.device.ip: a for a in assessments}
    assert by_ip["10.0.0.5"].isolation is None
    assert by_ip["10.0.0.9"].isolation is not None


# --- ordering: isolation state is attached before reports are written ----


def test_report_generation_sees_the_isolation_state(monkeypatch) -> None:
    """Attachment happens before the EOF report loop, so the PDF and its
    signature cover the enforcement result."""
    seen: List[Optional[object]] = []
    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})
    monkeypatch.setattr(
        runner_module,
        "generate_report",
        lambda assessment, sk, pk, output_dir: (seen.append(assessment.isolation), (None, None))[1],
    )

    run_capture(
        _FakeCaptureSource([_raw_packet()]), None, *_KEYS, isolation_backend=NoOpIsolationBackend()
    )

    assert len(seen) == 1
    assert seen[0] is not None


def test_enforcement_still_happens_during_packet_processing(monkeypatch) -> None:
    """Phase 14 timing is unchanged by Phase 3B: the backend is called
    per packet, not deferred to the attachment step at EOF."""
    order: List[str] = []

    class _Ordered(IsolationBackend):
        backend_name = "ordered"

        def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
            order.append("isolate")
            return IsolationOutcome(device_ip, risk_score, TS, True, False, "ordered", "ordered")

    _patch_assess(monkeypatch, {_IP: _assessment(_IP, 9, RiskCategory.HIGH)})
    monkeypatch.setattr(
        runner_module,
        "generate_report",
        lambda assessment, sk, pk, output_dir: (order.append("report"), (None, None))[1],
    )

    run_capture(_FakeCaptureSource([_raw_packet()]), None, *_KEYS, isolation_backend=_Ordered())

    assert order == ["isolate", "report"]


def test_isolation_state_does_not_alter_risk_ml_or_fusion_values(monkeypatch) -> None:
    original = _assessment(_IP, 9, RiskCategory.HIGH)
    _patch_assess(monkeypatch, {_IP: original})

    retained = _run(NoOpIsolationBackend())[0]

    assert retained.risk_assessment == original.risk_assessment
    assert retained.final_category == original.final_category
    assert retained.anomaly_assessment == original.anomaly_assessment
    assert retained.assessed_at == original.assessed_at
