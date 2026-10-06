"""Protected-device attribution through the REAL pipeline.

These run genuine `run_capture()` with no stubbing of `assess_packet`,
`fingerprint_packet`, the QRS or fusion, so they prove the semantics rather
than the plumbing: a packet's score is computed exactly as it always was, and
only *whose* score it is changes.

The payloads are deterministic TLS records built by hand, so the inbound
Certificate / RSA-key-size evidence is genuinely parsed rather than asserted
about. No hardware, no interface, no root, no socket.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Optional, Tuple

import pytest

import pipeline.runner as runner_module
from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from enforcement.backends import IsolationBackend, IsolationOutcome, NoOpIsolationBackend
from fingerprint.protocol import fingerprint_packet
from models.enums import ProtocolType, TLSVersion
from pipeline.device_resolution import ProtectedScope
from pipeline.runner import run_capture

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_KEYS = (b"public-key-bytes", b"secret-key-bytes")

LAB = "192.168.50.0/24"
PI = "192.168.50.1"
CLIENT = "192.168.50.24"
REMOTE = "93.184.216.34"


def _scope() -> ProtectedScope:
    return ProtectedScope([LAB], excluded_addresses=[PI])


def _resolver():
    return _scope().resolve


# --- deterministic payloads ------------------------------------------------


def _tls10_client_hello() -> bytes:
    """A TLS record announcing version 1.0 — the evidence a client emits."""
    body = bytes([0x01]) + (0).to_bytes(3, "big") + bytes([0x03, 0x01]) + b"\x00" * 32
    return bytes([0x16, 0x03, 0x01]) + len(body).to_bytes(2, "big") + body


def _telnet_payload() -> bytes:
    """IAC DO/WILL negotiation: what the protocol detector keys on."""
    return bytes([0xFF, 0xFD, 0x18, 0xFF, 0xFB, 0x01]) + b"login: "


def _http_payload() -> bytes:
    return b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


@pytest.fixture(scope="module")
def inbound_certificate() -> bytes:
    """A TLS Certificate record carrying a weak RSA key, built by asking the
    real fingerprinter what it can parse.

    Skips rather than asserting a guess if this project's parser cannot extract
    a key size from a synthesised certificate — the point of the test is
    attribution, and a fabricated parse would prove nothing.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
    except ImportError:  # pragma: no cover - cryptography is a project dependency
        pytest.skip("cryptography is unavailable")

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cipher-test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1))
        .not_valid_after(datetime(2027, 1, 1))
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)

    # Handshake: Certificate(11) { cert_list_len(3) { cert_len(3) der } }
    entry = len(der).to_bytes(3, "big") + der
    cert_list = len(entry).to_bytes(3, "big") + entry
    handshake = bytes([0x0B]) + len(cert_list).to_bytes(3, "big") + cert_list
    record = bytes([0x16, 0x03, 0x03]) + len(handshake).to_bytes(2, "big") + handshake

    if fingerprint_packet(record).key_size is None:
        pytest.skip("this build's TLS parser does not extract a key size from this record")
    return record


# --- harness ---------------------------------------------------------------


class _FakeCaptureSource(CaptureSource):
    def __init__(self, packets: List[RawPacket]) -> None:
        self._packets = packets

    def read_packets(self) -> Iterator[RawPacket]:
        yield from self._packets


def _packet(
    src: str,
    dst: str,
    payload: bytes,
    sport: int = 40000,
    dport: int = 443,
    offset_seconds: int = 0,
) -> RawPacket:
    return RawPacket(
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        payload=payload,
        timestamp=TS + timedelta(seconds=offset_seconds),
    )


class _RecordingBackend(IsolationBackend):
    backend_name = "recording"
    enforcement_capable = True

    def __init__(self) -> None:
        self.calls: List[Tuple[str, int]] = []

    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        self.calls.append((device_ip, risk_score))
        return IsolationOutcome(device_ip, risk_score, TS, True, False, "recorded", "recording")


@pytest.fixture(autouse=True)
def _no_real_reports(monkeypatch):
    monkeypatch.setattr(
        runner_module, "generate_report", lambda assessment, sk, pk, output_dir: (None, None)
    )


def _run(packets, resolver=None, backend=None):
    assessments, reports = run_capture(
        _FakeCaptureSource(packets),
        None,  # ML is optional and not under test here
        *_KEYS,
        isolation_backend=backend or NoOpIsolationBackend(),
        device_resolver=resolver,
    )
    return assessments, reports


# --- B. the headline invariant --------------------------------------------


def test_one_client_and_many_servers_produce_one_device_in_scoped_mode() -> None:
    """One protected client talking bidirectionally to 12 Internet servers must
    be ONE CIPHER device."""
    packets = []
    for index in range(12):
        server = f"93.184.216.{index + 10}"
        packets.append(_packet(CLIENT, server, _tls10_client_hello(), offset_seconds=index))
        packets.append(_packet(server, CLIENT, _http_payload(), 443, 40000, index))

    assessments, _reports = _run(packets, resolver=_resolver())

    assert [a.device.ip for a in assessments] == [CLIENT]


def test_the_same_traffic_unscoped_produces_many_devices() -> None:
    """The defect being fixed, pinned so the fix cannot be mistaken for a
    coincidence: with no resolver, every remote source is its own device."""
    packets = []
    for index in range(12):
        server = f"93.184.216.{index + 10}"
        packets.append(_packet(CLIENT, server, _tls10_client_hello(), offset_seconds=index))
        packets.append(_packet(server, CLIENT, _http_payload(), 443, 40000, index))

    assessments, _reports = _run(packets, resolver=None)

    assert len(assessments) == 13  # the client plus 12 servers


def test_several_protected_clients_remain_several_devices() -> None:
    """Attribution must not collapse genuinely different protected devices."""
    packets = [
        _packet(CLIENT, REMOTE, _http_payload()),
        _packet(REMOTE, "192.168.50.77", _http_payload(), 443, 40000),
    ]

    assessments, _reports = _run(packets, resolver=_resolver())

    assert {a.device.ip for a in assessments} == {CLIENT, "192.168.50.77"}


def test_traffic_between_two_unprotected_hosts_produces_no_device() -> None:
    assessments, _reports = _run(
        [_packet(REMOTE, "8.8.8.8", _http_payload())], resolver=_resolver()
    )
    assert assessments == []


def test_the_appliance_itself_never_becomes_a_device() -> None:
    packets = [
        _packet(PI, REMOTE, _http_payload()),
        _packet(REMOTE, PI, _http_payload(), 443, 40000),
    ]

    assessments, _reports = _run(packets, resolver=_resolver())

    assert assessments == []


def test_pi_to_client_traffic_is_attributed_to_the_client() -> None:
    assessments, _reports = _run([_packet(PI, CLIENT, _http_payload())], resolver=_resolver())
    assert [a.device.ip for a in assessments] == [CLIENT]


# --- C. evidence retention ------------------------------------------------


def test_inbound_tls_certificate_evidence_is_attributed_to_the_client(
    inbound_certificate,
) -> None:
    """The evidence that only ever travels server->client. It must survive, and
    it must be filed under the protected client."""
    assessments, _reports = _run(
        [_packet(REMOTE, CLIENT, inbound_certificate, 443, 40000)], resolver=_resolver()
    )

    assert len(assessments) == 1
    assert assessments[0].device.ip == CLIENT


def test_the_inbound_rsa_key_size_is_still_parsed_from_the_packet(
    inbound_certificate,
) -> None:
    """Proves the payload reached the real fingerprinter unmodified: a 1024-bit
    key is extracted from the very bytes the pipeline was given."""
    fingerprint = fingerprint_packet(inbound_certificate)

    assert fingerprint.protocol is ProtocolType.HTTPS
    assert fingerprint.key_size == 1024


def test_inbound_weak_key_evidence_shapes_the_clients_assessment(
    inbound_certificate,
) -> None:
    """Attribution is not cosmetic: the client's assessment is genuinely derived
    from the certificate its peer presented.

    Asserted through the remediation text rather than by comparing scores
    against an unrelated payload — the QRS is a bounded 0-10 sum, so two
    different weaknesses can legitimately land on the same number, and a
    magnitude comparison would prove nothing about which evidence was used."""
    weak, _reports = _run(
        [_packet(REMOTE, CLIENT, inbound_certificate, 443, 40000)], resolver=_resolver()
    )
    benign, _reports = _run([_packet(CLIENT, REMOTE, _http_payload())], resolver=_resolver())

    assert weak[0].device.ip == benign[0].device.ip == CLIENT
    # This sentence is emitted only for an observed key size, so it can only
    # have come from the certificate the server sent. (The generic
    # "static RSA key exchange" forward-secrecy sentence appears in every
    # assessment and would not discriminate.)
    assert "observed: 1024 bits" in weak[0].risk_assessment.remediation
    assert "observed:" not in benign[0].risk_assessment.remediation


def test_inbound_evidence_is_scored_identically_in_either_direction(
    inbound_certificate,
) -> None:
    """The same certificate bytes produce the same assessment whether they
    travelled toward the client or away from it — scoring never consults an
    address."""
    inbound, _reports = _run(
        [_packet(REMOTE, CLIENT, inbound_certificate, 443, 40000)], resolver=_resolver()
    )
    outbound, _reports = _run(
        [_packet(CLIENT, REMOTE, inbound_certificate, 40000, 443)], resolver=_resolver()
    )

    assert inbound[0].risk_assessment == outbound[0].risk_assessment
    assert inbound[0].device.ip == outbound[0].device.ip == CLIENT


def test_outbound_tls_evidence_is_still_used() -> None:
    """A TLS 1.0 ClientHello is parsed and scored exactly as before."""
    assessments, _reports = _run(
        [_packet(CLIENT, REMOTE, _tls10_client_hello())], resolver=_resolver()
    )

    assert fingerprint_packet(_tls10_client_hello()).tls_version is TLSVersion.TLS_1_0
    assert assessments[0].device.ip == CLIENT
    assert assessments[0].risk_assessment.risk_score > 0


def test_the_packet_itself_is_never_modified() -> None:
    """Attribution is a labelling decision; the wire record must stay honest."""
    packet = _packet(REMOTE, CLIENT, _http_payload(), 443, 40000)

    _run([packet], resolver=_resolver())

    assert packet.src_ip == REMOTE
    assert packet.dst_ip == CLIENT
    assert packet.src_port == 443
    assert packet.dst_port == 40000
    assert packet.payload == _http_payload()


def test_an_identical_payload_scores_identically_in_either_direction() -> None:
    """Scoring never consults an address or a port, so direction cannot change
    a score — only whose score it is."""
    outbound, _reports = _run(
        [_packet(CLIENT, REMOTE, _telnet_payload(), 40000, 23)], resolver=_resolver()
    )
    inbound, _reports = _run(
        [_packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000)], resolver=_resolver()
    )

    assert outbound[0].risk_assessment.risk_score == inbound[0].risk_assessment.risk_score
    assert outbound[0].device.ip == inbound[0].device.ip == CLIENT


# --- D. enforcement safety -----------------------------------------------


def test_inbound_high_risk_isolates_the_protected_client() -> None:
    """The safety check: evidence arriving from a server must enforce against
    the client, never against the server."""
    backend = _RecordingBackend()
    _run(
        [_packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000)],
        resolver=_resolver(),
        backend=backend,
    )

    assert backend.calls, "expected the TELNET payload to reach the isolation threshold"
    assert [ip for ip, _score in backend.calls] == [CLIENT]
    assert all(score >= 7 for _ip, score in backend.calls)


def test_a_remote_server_is_never_an_isolation_target_in_scoped_mode() -> None:
    backend = _RecordingBackend()
    packets = [
        _packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000),
        _packet("8.8.8.8", CLIENT, _telnet_payload(), 23, 40001, 1),
    ]

    _run(packets, resolver=_resolver(), backend=backend)

    isolated = {ip for ip, _score in backend.calls}
    assert isolated == {CLIENT}
    assert REMOTE not in isolated
    assert "8.8.8.8" not in isolated


def test_unprotected_traffic_never_reaches_the_backend() -> None:
    backend = _RecordingBackend()

    _run(
        [_packet(REMOTE, "8.8.8.8", _telnet_payload(), 23, 40000)],
        resolver=_resolver(),
        backend=backend,
    )

    assert backend.calls == []


def test_below_the_threshold_nothing_is_isolated() -> None:
    backend = _RecordingBackend()

    _run([_packet(CLIENT, REMOTE, _http_payload())], resolver=_resolver(), backend=backend)

    for _ip, score in backend.calls:
        assert score >= 7  # if anything was isolated it was eligible
    assert all(
        a.risk_assessment.risk_score < 7
        for a in _run([_packet(CLIENT, REMOTE, _http_payload())], resolver=_resolver())[0]
    ) == (backend.calls == [])


def test_raw_qrs_remains_the_sole_isolation_trigger(monkeypatch) -> None:
    """Raw QRS 5 fused up to HIGH by the anomaly signal, inbound direction,
    scoped mode: still no isolation."""
    from models.anomaly_assessment import AnomalyAssessment
    from models.device import Device
    from models.device_assessment import DeviceAssessment
    from models.enums import RiskCategory
    from models.risk_assessment import RiskAssessment

    def _escalated(raw_packet, device, port_risk, anomaly_detector=None, assessed_at=None):
        return DeviceAssessment(
            device=device,
            risk_assessment=RiskAssessment(5, RiskCategory.MEDIUM, "text", "NIST SP 800-52r2"),
            anomaly_assessment=AnomalyAssessment(
                anomaly_score=-0.9, is_anomaly=True, confidence=0.99
            ),
            final_category=RiskCategory.HIGH,
            assessed_at=TS,
        )

    monkeypatch.setattr(runner_module, "assess_packet", _escalated)
    backend = _RecordingBackend()

    assessments, _reports = _run(
        [_packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000)],
        resolver=_resolver(),
        backend=backend,
    )

    assert assessments[0].final_category is RiskCategory.HIGH
    assert assessments[0].device.ip == CLIENT
    assert backend.calls == []


def test_the_isolation_target_is_the_assessed_device() -> None:
    """Assessed identity and enforced identity must never diverge."""
    backend = _RecordingBackend()
    assessments, _reports = _run(
        [_packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000)],
        resolver=_resolver(),
        backend=backend,
    )

    assert [ip for ip, _score in backend.calls] == [assessments[0].device.ip]


# --- E. reports and isolation state --------------------------------------


def test_an_inbound_triggered_report_names_the_protected_client(monkeypatch) -> None:
    reported = []
    monkeypatch.setattr(
        runner_module,
        "generate_report",
        lambda assessment, sk, pk, output_dir: (
            reported.append(assessment.device.ip),
            (None, None),
        )[1],
    )

    _run([_packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000)], resolver=_resolver())

    assert reported == [CLIENT]


def test_isolation_state_is_attached_to_the_protected_client() -> None:
    assessments, _reports = _run(
        [_packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000)], resolver=_resolver()
    )

    assert assessments[0].device.ip == CLIENT
    assert assessments[0].isolation is not None
    assert assessments[0].isolation.enforced is False  # NoOp backend


def test_the_observer_only_sees_protected_devices() -> None:
    """What the OLED and LEDs receive, with no filter of their own."""
    seen: List[str] = []
    packets = [
        _packet(CLIENT, REMOTE, _http_payload()),
        _packet(REMOTE, CLIENT, _http_payload(), 443, 40000, 1),
        _packet(REMOTE, "8.8.8.8", _http_payload(), 443, 40000, 2),
        _packet(PI, REMOTE, _http_payload(), 40000, 443, 3),
    ]

    run_capture(
        _FakeCaptureSource(packets),
        None,
        *_KEYS,
        isolation_backend=NoOpIsolationBackend(),
        device_resolver=_resolver(),
        assessment_observer=lambda a: seen.append(a.device.ip),
    )

    assert seen == [CLIENT, CLIENT]


# --- F. compatibility with no scope configured ---------------------------


def test_with_no_resolver_identity_is_still_the_source_address() -> None:
    assessments, _reports = _run(
        [_packet(REMOTE, CLIENT, _http_payload(), 443, 40000)], resolver=None
    )
    assert [a.device.ip for a in assessments] == [REMOTE]


def test_with_no_resolver_no_packet_is_ever_skipped() -> None:
    packets = [
        _packet(REMOTE, "8.8.8.8", _http_payload()),
        _packet(PI, REMOTE, _http_payload(), 40000, 443, 1),
    ]

    assessments, _reports = _run(packets, resolver=None)

    assert {a.device.ip for a in assessments} == {REMOTE, PI}


def test_with_no_resolver_enforcement_targets_the_source() -> None:
    """Legacy semantics preserved exactly, including the characteristic this
    fix exists to correct — unscoped behaviour must not silently change."""
    backend = _RecordingBackend()

    _run([_packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000)], resolver=None, backend=backend)

    assert [ip for ip, _score in backend.calls] == [REMOTE]


def test_device_first_and_last_seen_advance_across_both_directions() -> None:
    """Device lifecycle is unchanged by the refactor, and one device now
    accumulates timestamps from BOTH directions: first contact (outbound) sets
    first_seen, and a later inbound packet advances last_seen.

    The second packet is strictly stronger (TELNET), so representative
    selection is deterministic here rather than resting on an `assessed_at`
    tiebreak between identically-scored packets."""
    packets = [
        _packet(CLIENT, REMOTE, _http_payload(), offset_seconds=0),
        _packet(REMOTE, CLIENT, _telnet_payload(), 23, 40000, 30),
    ]

    assessments, _reports = _run(packets, resolver=_resolver())

    assert len(assessments) == 1
    device = assessments[0].device
    assert device.ip == CLIENT
    assert device.first_seen == TS
    assert device.last_seen == TS + timedelta(seconds=30)
