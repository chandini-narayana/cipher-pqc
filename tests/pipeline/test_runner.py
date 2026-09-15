"""Unit tests for pipeline.runner.run_capture — the synchronous,
single-pass offline runtime orchestrator (docs/SDD.md Phase 11
addendum).

Uses fakes/spies for CaptureSource, assess_packet, and generate_report
so these tests stay fast and deterministic and don't depend on exact
QRS scoring thresholds or generate real PDFs — Phase 10's own test
suite remains responsible for PDF correctness.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Tuple

import pytest

from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from enforcement import IsolationBackend, IsolationOutcome, NoOpIsolationBackend
from fingerprint.protocol import fingerprint_packet
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.report_metadata import ReportMetadata
from models.risk_assessment import RiskAssessment
from risk.port_risk import port_risk_for_protocol

import pipeline.runner as runner_module
from pipeline.runner import run_capture

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

_HTTP_PAYLOAD = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
_MQTT_PAYLOAD = b"MQTT-CONNECT-PAYLOAD"


class _FakeCaptureSource(CaptureSource):
    def __init__(self, packets: List[RawPacket]) -> None:
        self._packets = packets

    def read_packets(self) -> Iterator[RawPacket]:
        yield from self._packets


def _raw_packet(src_ip: str, payload: bytes = _HTTP_PAYLOAD, timestamp: datetime = TS) -> RawPacket:
    return RawPacket(
        src_ip=src_ip,
        dst_ip="192.168.1.1",
        src_port=51000,
        dst_port=80,
        payload=payload,
        timestamp=timestamp,
    )


def _assessment(
    ip: str,
    category: RiskCategory,
    risk_score: int = 5,
    assessed_at: datetime = TS,
) -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(risk_score, category, "Some remediation text.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=category,
        assessed_at=assessed_at,
    )


_KEYS = (b"public-key-bytes", b"secret-key-bytes")
_NOOP_BACKEND = NoOpIsolationBackend()


class _SpyIsolationBackend(IsolationBackend):
    """Records every isolate() call (device_ip, risk_score) without
    logging noise or any real enforcement — for tests that need to
    observe *when*/*whether* the backend was invoked."""

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
        )


class _RaisingIsolationBackend(IsolationBackend):
    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        raise RuntimeError("simulated isolation backend failure")


@pytest.fixture(autouse=True)
def _no_real_report_generation(monkeypatch):
    """Default every test in this file to a harmless report-generation
    no-op, so tests that aren't specifically about reporting (device
    identity, assess_packet wiring, representative selection) never
    depend on real signing keys or render a real PDF — Phase 10's own
    test suite remains responsible for PDF correctness. Tests that
    exercise reporting behavior explicitly re-patch this themselves."""
    monkeypatch.setattr(
        runner_module, "generate_report", lambda assessment, sk, pk, output_dir: (None, None)
    )


# --- 1-5. device identity/lifecycle ---


def test_source_ip_used_as_phase1_device_id(monkeypatch) -> None:
    seen_devices = []

    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        seen_devices.append(device)
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    packet = _raw_packet("10.0.0.5")
    run_capture(_FakeCaptureSource([packet]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert seen_devices[0].ip == "10.0.0.5"


def test_first_packet_establishes_first_seen(monkeypatch) -> None:
    seen_devices = []
    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        seen_devices.append(device)
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    packet = _raw_packet("10.0.0.5", timestamp=TS)
    run_capture(_FakeCaptureSource([packet]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert seen_devices[0].first_seen == TS
    assert seen_devices[0].last_seen == TS


def test_later_packet_updates_last_seen(monkeypatch) -> None:
    seen_devices = []
    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        seen_devices.append(device)
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    later_ts = TS + timedelta(minutes=5)
    packets = [_raw_packet("10.0.0.5", timestamp=TS), _raw_packet("10.0.0.5", timestamp=later_ts)]
    run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert seen_devices[0].first_seen == TS
    assert seen_devices[0].last_seen == TS
    assert seen_devices[1].first_seen == TS  # preserved
    assert seen_devices[1].last_seen == later_ts


def test_out_of_order_packet_does_not_move_last_seen_backwards(monkeypatch) -> None:
    seen_devices = []
    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        seen_devices.append(device)
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    later_ts = TS + timedelta(minutes=5)
    earlier_ts = TS - timedelta(minutes=5)
    packets = [
        _raw_packet("10.0.0.5", timestamp=later_ts),
        _raw_packet("10.0.0.5", timestamp=earlier_ts),
    ]
    run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert seen_devices[0].last_seen == later_ts
    assert seen_devices[1].last_seen == later_ts  # unchanged by the earlier, out-of-order packet
    assert seen_devices[1].first_seen == later_ts  # first_contact was on the first-processed packet


def test_different_source_ips_tracked_separately(monkeypatch) -> None:
    seen_devices = []
    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        seen_devices.append(device)
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]
    assessments, _ = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    ips = {a.device.ip for a in assessments}
    assert ips == {"10.0.0.5", "10.0.0.6"}
    assert seen_devices[0].ip != seen_devices[1].ip


# --- 6-9. assessment wiring ---


def test_every_valid_packet_reaches_assess_packet(monkeypatch) -> None:
    call_count = 0
    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        nonlocal call_count
        call_count += 1
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6"), _raw_packet("10.0.0.7")]
    run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert call_count == 3


def test_existing_port_risk_policy_is_applied(monkeypatch) -> None:
    captured_port_risk = []
    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        captured_port_risk.append(port_risk)
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    packet = _raw_packet("10.0.0.5", payload=_MQTT_PAYLOAD)
    run_capture(_FakeCaptureSource([packet]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    expected = port_risk_for_protocol(fingerprint_packet(_MQTT_PAYLOAD).protocol)
    assert captured_port_risk == [expected]


def test_same_injected_anomaly_detector_is_reused(monkeypatch) -> None:
    captured_detectors = []
    real_assess_packet = runner_module.assess_packet

    def spy(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        captured_detectors.append(anomaly_detector)
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", spy)

    sentinel_detector = object()  # identity check only; never calls .predict_one in this test
    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]

    # anomaly_detector isn't actually invoked by our spy path below because
    # assess_packet only calls .predict_one when not None; use a detector
    # stub with predict_one so the real assess_packet path succeeds.
    class _StubDetector:
        def predict_one(self, features):
            return AnomalyAssessment(anomaly_score=0.1, is_anomaly=False, confidence=0.2)

    detector = _StubDetector()
    run_capture(_FakeCaptureSource(packets), detector, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert captured_detectors == [detector, detector]


def test_anomaly_detector_none_works(monkeypatch) -> None:
    packet = _raw_packet("10.0.0.5")
    assessments, _ = run_capture(_FakeCaptureSource([packet]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert len(assessments) == 1
    assert assessments[0].anomaly_assessment is None


# --- 10-13. representative selection ---


def test_high_replaces_medium(monkeypatch) -> None:
    responses = [
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5),
        _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=8),
    ]

    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return responses.pop(0)

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.5")]
    assessments, _ = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert len(assessments) == 1
    assert assessments[0].final_category == RiskCategory.HIGH


def test_medium_does_not_replace_high(monkeypatch) -> None:
    responses = [
        _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9),
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5),
    ]

    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return responses.pop(0)

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.5")]
    assessments, _ = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert assessments[0].final_category == RiskCategory.HIGH
    assert assessments[0].risk_assessment.risk_score == 9


def test_higher_qrs_wins_within_same_category(monkeypatch) -> None:
    responses = [
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=3),
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=6),
    ]

    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return responses.pop(0)

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.5")]
    assessments, _ = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert assessments[0].risk_assessment.risk_score == 6


def test_later_assessment_wins_on_category_and_score_tie(monkeypatch) -> None:
    earlier_ts = TS
    later_ts = TS + timedelta(minutes=1)
    responses = [
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5, assessed_at=earlier_ts),
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5, assessed_at=later_ts),
    ]

    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return responses.pop(0)

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.5")]
    assessments, _ = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert assessments[0].assessed_at == later_ts


# --- return-shape contract: run_capture retains real ReportMetadata ---


def test_returned_report_metadata_corresponds_to_the_written_pdf(tmp_path, monkeypatch) -> None:
    """Uses the real generate_report (no mocking) end-to-end: confirms
    run_capture's second return value is (Path, ReportMetadata) pairs,
    not just paths, and that the metadata genuinely describes the file
    written at that path."""
    from reports.pdf_generator import generate_report as real_generate_report
    from signing import generate_keypair

    monkeypatch.setattr(runner_module, "generate_report", real_generate_report)

    public_key, secret_key = generate_keypair()
    packet = _raw_packet("10.0.0.5", payload=b"\x16\x03\x03\x00\x10" + b"A" * 16)

    assessments, reports = run_capture(
        _FakeCaptureSource([packet]),
        None,
        public_key,
        secret_key,
        isolation_backend=_NOOP_BACKEND,
        report_output_dir=tmp_path,
    )

    assert len(assessments) == 1
    assert len(reports) == 1  # this fixture payload lands in a flagged category

    path, metadata = reports[0]
    assert isinstance(metadata, ReportMetadata)
    assert path.exists()
    assert path.name == f"{metadata.report_id}.pdf"
    assert metadata.device_ip == "10.0.0.5"


# --- 14-19. reporting ---


def _patch_assess_packet_returning(monkeypatch, assessment_by_ip):
    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return assessment_by_ip[device.ip]

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)


def test_low_device_gets_no_automatic_report(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.LOW, risk_score=1)}
    )
    report_calls = []
    monkeypatch.setattr(
        runner_module,
        "generate_report",
        lambda assessment, sk, pk, output_dir: report_calls.append(assessment) or (None, None),
    )

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert report_calls == []


def test_medium_device_gets_one_report(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5)}
    )
    report_calls = []

    def fake_generate_report(assessment, sk, pk, output_dir):
        report_calls.append(assessment)
        return (f"/fake/{assessment.device.ip}.pdf", None)

    monkeypatch.setattr(runner_module, "generate_report", fake_generate_report)

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert len(report_calls) == 1


def test_high_device_gets_one_report(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9)}
    )
    report_calls = []

    def fake_generate_report(assessment, sk, pk, output_dir):
        report_calls.append(assessment)
        return (f"/fake/{assessment.device.ip}.pdf", None)

    monkeypatch.setattr(runner_module, "generate_report", fake_generate_report)

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert len(report_calls) == 1


def test_multiple_flagged_packets_from_same_ip_still_generate_one_report(monkeypatch) -> None:
    responses = [
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5),
        _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=8),
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=4),
    ]

    def fake_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return responses.pop(0)

    monkeypatch.setattr(runner_module, "assess_packet", fake_assess_packet)

    report_calls = []

    def fake_generate_report(assessment, sk, pk, output_dir):
        report_calls.append(assessment)
        return (f"/fake/{assessment.device.ip}.pdf", None)

    monkeypatch.setattr(runner_module, "generate_report", fake_generate_report)

    packets = [_raw_packet("10.0.0.5")] * 3
    run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert len(report_calls) == 1
    assert report_calls[0].final_category == RiskCategory.HIGH


def test_multiple_flagged_device_ips_each_generate_one_report(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5),
            "10.0.0.6": _assessment("10.0.0.6", RiskCategory.HIGH, risk_score=9),
        },
    )
    report_calls = []

    def fake_generate_report(assessment, sk, pk, output_dir):
        report_calls.append(assessment)
        return (f"/fake/{assessment.device.ip}.pdf", None)

    monkeypatch.setattr(runner_module, "generate_report", fake_generate_report)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]
    run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    reported_ips = {a.device.ip for a in report_calls}
    assert reported_ips == {"10.0.0.5", "10.0.0.6"}


def test_report_generation_failure_for_one_device_does_not_stop_others(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9),
            "10.0.0.6": _assessment("10.0.0.6", RiskCategory.HIGH, risk_score=9),
        },
    )
    report_calls = []

    def fake_generate_report(assessment, sk, pk, output_dir):
        if assessment.device.ip == "10.0.0.5":
            raise RuntimeError("simulated report failure")
        report_calls.append(assessment)
        return (f"/fake/{assessment.device.ip}.pdf", None)

    monkeypatch.setattr(runner_module, "generate_report", fake_generate_report)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]
    assessments, reports = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert len(assessments) == 2  # both devices still assessed
    assert len(reports) == 1  # only the successful report is returned
    assert report_calls[0].device.ip == "10.0.0.6"


# --- 20. fault isolation for bad packets ---


def test_bad_packet_does_not_abort_remaining_packets(monkeypatch) -> None:
    real_assess_packet = runner_module.assess_packet

    def flaky_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        if device.ip == "10.0.0.5":
            raise ValueError("simulated bad packet")
        return real_assess_packet(raw_packet, device, port_risk, anomaly_detector, assessed_at)

    monkeypatch.setattr(runner_module, "assess_packet", flaky_assess_packet)

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]
    assessments, _ = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_NOOP_BACKEND)

    assert len(assessments) == 1
    assert assessments[0].device.ip == "10.0.0.6"


def test_keyboard_interrupt_is_not_suppressed(monkeypatch) -> None:
    def interrupting_assess_packet(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(runner_module, "assess_packet", interrupting_assess_packet)

    with pytest.raises(KeyboardInterrupt):
        run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=_NOOP_BACKEND)


# --- Phase 14: high-risk isolation enforcement ---


def test_qrs_below_threshold_does_not_call_isolation_backend(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=6)}
    )
    backend = _SpyIsolationBackend()

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == []


def test_qrs_exactly_at_threshold_calls_backend_immediately(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=7)}
    )
    backend = _SpyIsolationBackend()

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == [("10.0.0.5", 7)]


def test_qrs_above_threshold_calls_backend(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9)}
    )
    backend = _SpyIsolationBackend()

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == [("10.0.0.5", 9)]


def test_ml_escalated_high_with_raw_qrs_below_threshold_does_not_call_backend(monkeypatch) -> None:
    """The critical Phase 14 policy case: risk_fusion escalated MEDIUM
    (raw QRS=5) to a HIGH final_category because Isolation Forest
    flagged an anomaly. Enforcement must key off the raw QRS only."""
    escalated = DeviceAssessment(
        device=Device.first_contact("10.0.0.5", TS),
        risk_assessment=RiskAssessment(5, RiskCategory.MEDIUM, "text", "NIST SP 800-52r2"),
        anomaly_assessment=AnomalyAssessment(anomaly_score=0.9, is_anomaly=True, confidence=0.9),
        final_category=RiskCategory.HIGH,  # escalated by fusion, not by raw QRS
        assessed_at=TS,
    )
    monkeypatch.setattr(runner_module, "assess_packet", lambda *a, **k: escalated)
    backend = _SpyIsolationBackend()

    run_capture(_FakeCaptureSource([_raw_packet("10.0.0.5")]), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == []


def test_repeated_high_risk_packets_from_same_ip_cause_one_isolation_attempt(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9)}
    )
    backend = _SpyIsolationBackend()

    packets = [_raw_packet("10.0.0.5")] * 5
    run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=backend)

    assert backend.calls == [("10.0.0.5", 9)]


def test_two_distinct_high_risk_ips_each_get_one_attempt(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9),
            "10.0.0.6": _assessment("10.0.0.6", RiskCategory.HIGH, risk_score=8),
        },
    )
    backend = _SpyIsolationBackend()

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6"), _raw_packet("10.0.0.5")]
    run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=backend)

    assert sorted(backend.calls) == [("10.0.0.5", 9), ("10.0.0.6", 8)]


def test_isolation_backend_exception_does_not_stop_later_packet_processing(monkeypatch) -> None:
    _patch_assess_packet_returning(
        monkeypatch,
        {
            "10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9),
            "10.0.0.6": _assessment("10.0.0.6", RiskCategory.HIGH, risk_score=9),
        },
    )
    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.6")]

    assessments, _ = run_capture(
        _FakeCaptureSource(packets), None, *_KEYS, isolation_backend=_RaisingIsolationBackend()
    )

    # Both devices were still fully assessed despite the backend raising
    # for each of them — an isolation failure must not abort the run,
    # and must not prevent the assessment from being recorded either.
    assert {a.device.ip for a in assessments} == {"10.0.0.5", "10.0.0.6"}


def test_isolation_is_invoked_during_packet_processing_not_deferred_to_reporting(monkeypatch) -> None:
    """Confirms enforcement timing: should_isolate/backend.isolate() must
    happen immediately per-packet, before the EOF report-generation loop
    — not deferred to end-of-capture representative selection."""
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9)}
    )
    call_order = []

    class _OrderTrackingBackend(IsolationBackend):
        def isolate(self, device_ip, risk_score):
            call_order.append("isolate")
            return IsolationOutcome(device_ip, risk_score, TS, True, False, "test")

    def fake_generate_report(assessment, sk, pk, output_dir):
        call_order.append("generate_report")
        return (f"/fake/{assessment.device.ip}.pdf", None)

    monkeypatch.setattr(runner_module, "generate_report", fake_generate_report)

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=_OrderTrackingBackend(),
    )

    assert call_order == ["isolate", "generate_report"]


def test_isolation_threshold_parameter_is_honored_without_changing_the_default(monkeypatch) -> None:
    """A custom threshold changes eligibility for this call only — the
    production default (7) is untouched elsewhere."""
    _patch_assess_packet_returning(
        monkeypatch, {"10.0.0.5": _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5)}
    )
    backend = _SpyIsolationBackend()

    run_capture(
        _FakeCaptureSource([_raw_packet("10.0.0.5")]),
        None,
        *_KEYS,
        isolation_backend=backend,
        risk_isolation_threshold=5,
    )

    assert backend.calls == [("10.0.0.5", 5)]


def test_reporting_and_representative_selection_are_unaffected_by_isolation(monkeypatch) -> None:
    """Item 8-10: reporting (one PDF per flagged device, after EOF) and
    representative selection are unchanged by Phase 14 — enforcement is
    an independent side effect of per-packet processing."""
    responses = [
        _assessment("10.0.0.5", RiskCategory.MEDIUM, risk_score=5),
        _assessment("10.0.0.5", RiskCategory.HIGH, risk_score=9),
    ]
    monkeypatch.setattr(
        runner_module, "assess_packet", lambda *a, **k: responses.pop(0)
    )
    report_calls = []
    monkeypatch.setattr(
        runner_module,
        "generate_report",
        lambda assessment, sk, pk, output_dir: (report_calls.append(assessment), (None, None))[1],
    )
    backend = _SpyIsolationBackend()

    packets = [_raw_packet("10.0.0.5"), _raw_packet("10.0.0.5")]
    assessments, _ = run_capture(_FakeCaptureSource(packets), None, *_KEYS, isolation_backend=backend)

    assert len(assessments) == 1
    assert assessments[0].final_category == RiskCategory.HIGH  # representative selection unchanged
    assert len(report_calls) == 1  # still exactly one report, at EOF
    assert backend.calls == [("10.0.0.5", 9)]  # isolation attempted once, on the HIGH packet


# --- 21-24. boundaries (static dependency checks) ---


def test_runner_module_has_no_forbidden_dependencies() -> None:
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(runner_module))
    top_level_modules = set()
    full_module_paths = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_modules.add(alias.name.split(".")[0])
                full_module_paths.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level_modules.add(node.module.split(".")[0])
            full_module_paths.add(node.module)

    forbidden_top_level = {"threading", "flask", "dashboard", "frontend"}
    forbidden_exact = {"utils.registry", "capture.live_source"}

    assert not (top_level_modules & forbidden_top_level)
    assert not (full_module_paths & forbidden_exact)
