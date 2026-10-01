"""Phase 2D pipeline-aligned training and validation cohorts
(docs/SDD.md's Phase 2D addendum).

GROUND TRUTH AND PACKET CONSTRUCTION ONLY. This module builds controlled
packet payloads and declares each observation's a-priori label. It fits
nothing, scores nothing, and never imports ml/ beyond nothing at all — the
feature extraction and model work live in train_pipeline_aligned_model.py.

THREE COHORTS, THREE DISJOINT SEED NAMESPACES. The Phase 2A/2B N=24 binary
cohort is a FROZEN TEST SET and is built elsewhere
(tests/fixtures/generate_labelled_evaluation_fixtures.py) from seeds prefixed
`labelled-`. This module uses `p2d-train-` and `p2d-val-` exclusively, so no
payload here can coincide with a frozen-test payload. A test asserts the
resulting feature-vector sets are disjoint from the frozen test set's, and that
training and validation are disjoint from each other.

WHY THE TRAINING CORPUS IS SAFE-ONLY. Isolation Forest is an unsupervised
outlier detector: it learns what normal looks like. The training corpus is
therefore restricted to observations the external rubric calls SAFE without
qualification — properly configured TLS 1.3 handshakes, encrypted application
data, and certificates carrying RSA keys of at least 2048 bits. TLS 1.2 is
deliberately EXCLUDED from the training corpus even though SP 800-52r2 permits
it, because a single packet cannot establish its negotiated cipher suite, so it
is not unambiguously benign. That is a pre-declared construction decision, made
before any model was fitted and without reference to any test-set outcome.

WHAT THE PHASE 2B MISMATCH REQUIRES OF THIS CORPUS. The investigation recorded
in the Phase 2D report established that two feature patterns on real pipeline
vectors are CORRECT packet-level absence, not defects:

  * `key_size_observed = 0` for handshake Hello messages, because a Hello
    carries no certificate, and `tls_version_observed = 0` for Certificate
    messages, because a Certificate carries no version field. The two are
    mutually exclusive per packet on the TLS wire — no single packet can
    present both, which is precisely what every row of the old synthetic
    training matrix did present.
  * `forward_secrecy = 0` on every observation, because
    fingerprint.protocol.fingerprint_packet() never attempts cipher-suite
    classification and so never has grounds to report True.

This corpus therefore reproduces those patterns exactly, by being built from
real single packets rather than from assembled feature rows. Nothing in the
fingerprinter was changed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterator, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from scapy.all import IP, TCP, Ether, wrpcap

from tests.fixtures.generate_evaluation_fixtures import _filler
from tests.fixtures.generate_labelled_evaluation_fixtures import (
    _EXT_ALPN,
    _EXT_EXTENDED_MASTER_SECRET,
    _EXT_PADDING,
    _EXT_PSK_KEY_EXCHANGE_MODES,
    _EXT_RECORD_SIZE_LIMIT,
    _EXT_SESSION_TICKET,
    _EXT_STATUS_REQUEST,
    _EXT_SUPPORTED_VERSIONS,
    _GROUP_SECP256R1,
    _GROUP_SECP384R1,
    _GROUP_X25519,
    _GROUP_X25519_MLKEM768,
    _MLKEM768_CLIENT_SHARE_LEN,
    _MLKEM768_SERVER_SHARE_LEN,
    _X25519_SHARE_LEN,
    _alpn_extension,
    _cipher_suite_bytes,
    _client_key_share_extension,
    _extension,
    _handshake_record,
    _server_key_share_extension,
    _server_name_extension,
    _signature_algorithms_extension,
    _supported_groups_extension,
    _u16,
)

FIXTURES_DIR = __import__("pathlib").Path(__file__).resolve().parent

TRAIN_PCAP = FIXTURES_DIR / "pipeline_train_safe.pcap"
VALIDATION_PCAP = FIXTURES_DIR / "pipeline_validation.pcap"

TRAIN_SEED_PREFIX = "p2d-train"
VALIDATION_SEED_PREFIX = "p2d-val"
FROZEN_TEST_SEED_PREFIX = "labelled"

LABEL_SAFE = "SAFE"
LABEL_RISKY = "RISKY"

_CLIENT_HELLO = 0x01
_SERVER_HELLO = 0x02
_CERTIFICATE = 0x0B

_TLS13_SUITE_SETS = (
    (0x1301, 0x1302, 0x1303),
    (0x1301, 0x1302),
    (0x1302, 0x1303),
)
_ALPN_SETS = (
    (b"h2", b"http/1.1"),
    (b"h2",),
    (b"http/1.1",),
)
_SNI_HOSTS = (
    b"telemetry.hospital.example",
    b"pump-07.ward-3.hospital.example",
    b"api.example",
    b"monitor-gateway.clinic.hospital.example",
)
_TICKET_LENGTHS = (0, 32, 64, 96, 128)
_PAD_TARGETS = (0, 512, 768, 1024)
_LEGACY_SUITES = (0x000A, 0x002F, 0x0035, 0x0005)
_TLS12_AEAD_SUITES = (0xC02B, 0xC02F, 0xC02C, 0xC030)


@dataclass(frozen=True)
class PipelineObservation:
    """One controlled observation: its packet bytes plus its a-priori label.

    `label` is assigned from the external standards rubric at construction
    time, never from any model output or score.
    """

    observation_id: str
    cohort: str
    label: str
    family: str
    src_ip: str
    dst_port: int
    payload: bytes

    @property
    def is_risky(self) -> bool:
        return self.label == LABEL_RISKY


# --- SAFE families: properly configured TLS 1.3 --------------------------


def build_tls13_client_hello_variant(
    seed_label: str,
    hybrid: bool,
    ticket_length: int,
    alpn: Tuple[bytes, ...],
    sni: bytes,
    suites: Tuple[int, ...],
    pad_to: int,
    session_id: bool = True,
) -> bytes:
    """A properly configured TLS 1.3 ClientHello, varied across the dimensions
    a real client genuinely varies: offered groups, resumption-ticket size,
    ALPN set, server name, cipher-suite subset, RFC 7685 padding target and
    compatibility session_id.

    Every variant still negotiates TLS 1.3 via `supported_versions`, offers
    AEAD-only suites, and carries an ephemeral key share — so every variant is
    SAFE under the rubric. Padding, where applied, is correctly ZERO-filled.
    """
    groups: List[int] = [_GROUP_X25519, _GROUP_SECP256R1, _GROUP_SECP384R1]
    shares = [(_GROUP_X25519, _filler(f"{seed_label}-x25519", _X25519_SHARE_LEN))]
    if hybrid:
        groups = [_GROUP_X25519_MLKEM768] + groups
        shares = [
            (
                _GROUP_X25519_MLKEM768,
                _filler(f"{seed_label}-mlkem", _MLKEM768_CLIENT_SHARE_LEN),
            )
        ] + shares

    extensions = (
        _server_name_extension(sni)
        + _extension(_EXT_STATUS_REQUEST, bytes([0x01]) + _u16(0) + _u16(0))
        + _supported_groups_extension(groups)
        + _signature_algorithms_extension()
        + _alpn_extension(list(alpn))
        + _client_key_share_extension(shares)
        + _extension(_EXT_SUPPORTED_VERSIONS, bytes([0x04, 0x03, 0x04, 0x03, 0x03]))
        + _extension(_EXT_PSK_KEY_EXCHANGE_MODES, bytes([0x01, 0x01]))
        + _extension(_EXT_EXTENDED_MASTER_SECRET, b"")
        + _extension(_EXT_RECORD_SIZE_LIMIT, _u16(16385))
    )
    if ticket_length:
        extensions += _extension(
            _EXT_SESSION_TICKET, _filler(f"{seed_label}-ticket", ticket_length)
        )

    def assemble(extension_bytes: bytes) -> bytes:
        session = (
            bytes([0x20]) + _filler(f"{seed_label}-session", 32)
            if session_id
            else bytes([0x00])
        )
        body = (
            bytes([0x03, 0x03])
            + _filler(f"{seed_label}-random", 32)
            + session
            + _cipher_suite_bytes(list(suites))
            + bytes([0x01, 0x00])
            + _u16(len(extension_bytes))
            + extension_bytes
        )
        return _handshake_record(_CLIENT_HELLO, body, record_minor=0x01)

    packet = assemble(extensions)
    if pad_to and len(packet) < pad_to:
        pad_length = max(0, pad_to - len(packet) - 4)
        packet = assemble(extensions + _extension(_EXT_PADDING, bytes(pad_length)))
    return packet


def build_tls13_server_hello_variant(
    seed_label: str, hybrid: bool, echo_session_id: bool, suite: int
) -> bytes:
    """A properly configured TLS 1.3 ServerHello. Never carries RFC 7685
    padding, because a server does not echo it."""
    if hybrid:
        key_share = _server_key_share_extension(
            _GROUP_X25519_MLKEM768,
            _filler(f"{seed_label}-mlkem-ct", _MLKEM768_SERVER_SHARE_LEN),
        )
    else:
        key_share = _server_key_share_extension(
            _GROUP_X25519, _filler(f"{seed_label}-x25519", _X25519_SHARE_LEN)
        )

    extensions = _extension(_EXT_SUPPORTED_VERSIONS, bytes([0x03, 0x04])) + key_share
    session = (
        bytes([0x20]) + _filler(f"{seed_label}-session", 32)
        if echo_session_id
        else bytes([0x00])
    )
    body = (
        bytes([0x03, 0x03])
        + _filler(f"{seed_label}-random", 32)
        + session
        + _u16(suite)
        + bytes([0x00])
        + _u16(len(extensions))
        + extensions
    )
    return _handshake_record(_SERVER_HELLO, body, record_minor=0x03)


def build_application_data_record(seed_label: str, payload_length: int) -> bytes:
    """A TLS Application Data record (content type 0x17) carrying ciphertext —
    legitimately secure traffic, and the family that yields high entropy with
    neither a version nor a key size observable."""
    filler = _filler(f"{seed_label}-appdata", payload_length)
    return bytes([0x17, 0x03, 0x03]) + _u16(len(filler)) + filler


# --- certificate family (the only key_size_observed=1 family) ------------

_RSA_KEY_CACHE: dict = {}


def _rsa_key(bits: int, index: int):
    """Cache generated RSA keys: key generation is slow, and varying the
    certificate's serial number already produces distinct DER (and therefore
    distinct payload bytes and feature vectors) without a fresh keypair."""
    cached = _RSA_KEY_CACHE.get((bits, index))
    if cached is None:
        cached = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        _RSA_KEY_CACHE[(bits, index)] = cached
    return cached


def build_certificate_record(bits: int, key_index: int, serial: int, common_name: str) -> bytes:
    """A real TLS Certificate handshake message carrying a genuine self-signed
    X.509 certificate, parsed for real by
    fingerprint.tls.extract_rsa_key_size().

    NOT byte-reproducible across machines: `rsa.generate_private_key()` is
    random. This is accepted and reported — the family exists so the model sees
    `key_size_observed = 1` as normal, and the feature that matters
    (`key_size`) is exactly `bits` regardless of which key was drawn.
    """
    key = _rsa_key(bits, key_index)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before = datetime(2020, 1, 1, tzinfo=timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    certificate_list = len(der).to_bytes(3, "big") + der
    body = len(certificate_list).to_bytes(3, "big") + certificate_list
    return _handshake_record(_CERTIFICATE, body, record_minor=0x03)


# --- RISKY families (validation cohort only) ----------------------------


def build_legacy_client_hello_variant(
    seed_label: str, record_minor: int, sni: bytes, suites: Tuple[int, ...]
) -> bytes:
    """A pre-1.3 ClientHello for TLS 1.0 ({3,1}), 1.1 ({3,2}) or 1.2 ({3,3}),
    sending no `supported_versions` extension — correct, since that extension
    is TLS 1.3-only."""
    extensions = (
        _server_name_extension(sni)
        + _supported_groups_extension([_GROUP_X25519, _GROUP_SECP256R1])
        + _signature_algorithms_extension()
    )
    body = (
        bytes([0x03, record_minor])
        + _filler(f"{seed_label}-random", 32)
        + bytes([0x00])
        + _cipher_suite_bytes(list(suites))
        + bytes([0x01, 0x00])
        + _u16(len(extensions))
        + extensions
    )
    return _handshake_record(_CLIENT_HELLO, body, record_minor=record_minor)


def build_http_request_variant(
    seed_label: str, method: bytes, path: bytes, host: bytes, trace_length: int = 1
) -> bytes:
    """A plaintext HTTP/1.1 request — cleartext, therefore RISKY."""
    body = b""
    if method == b"POST":
        body = (
            b'{"device":"' + seed_label.encode("ascii") + b'","credential":"cipher-eval-placeholder"}'
        )
    # Two headers carry the variation. X-Request-Id makes the payload BYTES
    # distinct; X-Trace has a per-observation LENGTH, which matters because
    # payload length is itself one of the twelve features — without it, two
    # requests of equal length could still vectorize identically even though
    # their bytes differ.
    head = (
        method + b" " + path + b" HTTP/1.1\r\n"
        b"Host: " + host + b"\r\n"
        b"User-Agent: cipher-p2d\r\n"
        b"X-Request-Id: " + seed_label.encode("ascii") + b"\r\n"
        b"X-Trace: " + (b"t" * max(1, trace_length)) + b"\r\n"
    )
    if body:
        head += b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode("ascii") + b"\r\n"
    return head + b"\r\n" + body


def build_http_response_variant(seed_label: str, status: bytes, payload: bytes) -> bytes:
    """A plaintext HTTP/1.1 response — cleartext, therefore RISKY."""
    return (
        b"HTTP/1.1 " + status + b"\r\n"
        b"Content-Type: application/json\r\n"
        b"Server: cipher-p2d/" + seed_label.encode("ascii") + b"\r\n"
        b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
        b"\r\n" + payload
    )


def build_mqtt_connect_variant(client_id: bytes, keep_alive: int) -> bytes:
    """A real MQTT 3.1.1 CONNECT packet with no TLS — cleartext, therefore
    RISKY."""
    variable_header = (
        _u16(len(b"MQTT")) + b"MQTT" + bytes([0x04]) + bytes([0x02]) + _u16(keep_alive)
    )
    remaining = variable_header + _u16(len(client_id)) + client_id

    length_bytes = bytearray()
    n = len(remaining)
    while True:
        byte = n % 128
        n //= 128
        if n > 0:
            byte |= 0x80
        length_bytes.append(byte)
        if n == 0:
            break
    return bytes([0x10]) + bytes(length_bytes) + remaining


def build_telnet_negotiation_variant(options: Tuple[int, ...]) -> bytes:
    """A Telnet option-negotiation burst — cleartext remote shell, therefore
    RISKY. `options` is a flat (command, option) sequence."""
    out = bytearray()
    for index in range(0, len(options) - 1, 2):
        out += bytes([0xFF, options[index], options[index + 1]])
    return bytes(out)


# --- cohort assembly ----------------------------------------------------


def _ip_for(index: int, third_octet: int) -> str:
    """Unique source IP per observation. The pipeline identifies a device by
    src_ip, so distinct addresses keep each observation an independent device."""
    return f"10.{third_octet}.{index // 250}.{1 + index % 250}"


def _safe_observation_payloads(prefix: str) -> Iterator[Tuple[str, str, bytes]]:
    """Deterministically enumerate SAFE payloads as (family, seed_label, payload).

    The enumeration is a fixed nested walk over legitimate configuration
    dimensions — not random noise, and not one template mutated by a counter.
    """
    counter = 0
    # TLS 1.3 ClientHello: the widest family, as in real traffic.
    for hybrid in (False, True):
        for ticket_length in _TICKET_LENGTHS:
            for alpn_index, alpn in enumerate(_ALPN_SETS):
                for sni_index, sni in enumerate(_SNI_HOSTS):
                    for suite_index, suites in enumerate(_TLS13_SUITE_SETS):
                        for pad_to in _PAD_TARGETS:
                            counter += 1
                            seed = (
                                f"{prefix}-ch-{int(hybrid)}-{ticket_length}-"
                                f"{alpn_index}-{sni_index}-{suite_index}-{pad_to}"
                            )
                            yield (
                                "tls13_client_hello",
                                seed,
                                build_tls13_client_hello_variant(
                                    seed,
                                    hybrid=hybrid,
                                    ticket_length=ticket_length,
                                    alpn=alpn,
                                    sni=sni,
                                    suites=suites,
                                    pad_to=pad_to,
                                    session_id=(counter % 7 != 0),
                                ),
                            )


def _server_hello_payloads(prefix: str, count: int) -> List[Tuple[str, str, bytes]]:
    out = []
    index = 0
    for hybrid in (False, True):
        for echo in (True, False):
            for suite in (0x1301, 0x1302, 0x1303):
                for variation in range(12):
                    if len(out) >= count:
                        return out
                    index += 1
                    seed = f"{prefix}-sh-{int(hybrid)}-{int(echo)}-{suite:04x}-{variation}"
                    out.append(
                        (
                            "tls13_server_hello",
                            seed,
                            build_tls13_server_hello_variant(
                                seed, hybrid=hybrid, echo_session_id=echo, suite=suite
                            ),
                        )
                    )
    return out


def _application_data_payloads(prefix: str, count: int) -> List[Tuple[str, str, bytes]]:
    out = []
    length = 64
    step = 19
    for index in range(count):
        seed = f"{prefix}-appdata-{index}"
        out.append(
            ("tls_application_data", seed, build_application_data_record(seed, length))
        )
        length += step
        if length > 1400:
            length = 64 + (index % step)
    return out


def _certificate_payloads(prefix: str, count: int) -> List[Tuple[str, str, bytes]]:
    """Strong-RSA certificate records: the only SAFE family producing
    key_size_observed = 1, so the model must see it as normal."""
    out = []
    plan = [(2048, 0), (3072, 0), (4096, 0), (2048, 1), (3072, 1)]
    # The cohort prefix must reach the certificate CONTENT, not just the seed
    # label: a certificate is fully determined by its key, serial and subject
    # name, so without this two cohorts would emit byte-identical certificates
    # and the cohorts would overlap.
    serial_base = 1 + (int(hashlib.sha256(prefix.encode("utf-8")).hexdigest()[:8], 16) % 900_000)
    serial = serial_base
    while len(out) < count:
        for bits, key_index in plan:
            if len(out) >= count:
                break
            serial += 1
            seed = f"{prefix}-cert-{bits}-{key_index}-{serial}"
            out.append(
                (
                    f"certificate_rsa{bits}",
                    seed,
                    build_certificate_record(
                        bits, key_index, serial, f"{prefix}-{bits}-{serial}.invalid"
                    ),
                )
            )
    return out


TRAIN_CLIENT_HELLO_COUNT = 450
TRAIN_SERVER_HELLO_COUNT = 120
TRAIN_APPLICATION_DATA_COUNT = 70
TRAIN_CERTIFICATE_COUNT = 60

VALIDATION_SAFE_PER_FAMILY = (40, 18, 12, 10)  # CH, SH, appdata, certificates
VALIDATION_RISKY_PLAN = {
    "tls10_client_hello": 14,
    "tls11_client_hello": 14,
    "weak_rsa_certificate": 12,
    "http_cleartext": 16,
    "mqtt_no_tls": 12,
    "telnet": 12,
}


def build_training_observations() -> List[PipelineObservation]:
    """The SAFE-only pipeline-aligned training corpus."""
    payloads: List[Tuple[str, str, bytes]] = []
    for item in _safe_observation_payloads(TRAIN_SEED_PREFIX):
        payloads.append(item)
        if len(payloads) >= TRAIN_CLIENT_HELLO_COUNT:
            break
    payloads += _server_hello_payloads(TRAIN_SEED_PREFIX, TRAIN_SERVER_HELLO_COUNT)
    payloads += _application_data_payloads(TRAIN_SEED_PREFIX, TRAIN_APPLICATION_DATA_COUNT)
    payloads += _certificate_payloads(TRAIN_SEED_PREFIX, TRAIN_CERTIFICATE_COUNT)

    return [
        PipelineObservation(
            observation_id=seed,
            cohort="train",
            label=LABEL_SAFE,
            family=family,
            src_ip=_ip_for(index, 10),
            dst_port=443,
            payload=payload,
        )
        for index, (family, seed, payload) in enumerate(payloads)
    ]


def _validation_safe_payloads() -> List[Tuple[str, str, bytes]]:
    ch_count, sh_count, ad_count, cert_count = VALIDATION_SAFE_PER_FAMILY
    payloads: List[Tuple[str, str, bytes]] = []
    # A different walk order from training, so validation is not a prefix of it.
    taken = 0
    for item in _safe_observation_payloads(VALIDATION_SEED_PREFIX):
        taken += 1
        if taken % 3 == 0:  # decimate, giving a different configuration mix
            payloads.append(item)
        if len(payloads) >= ch_count:
            break
    payloads += _server_hello_payloads(VALIDATION_SEED_PREFIX, sh_count)
    payloads += _application_data_payloads(VALIDATION_SEED_PREFIX, ad_count)
    payloads += _certificate_payloads(VALIDATION_SEED_PREFIX, cert_count)
    return payloads


def _validation_risky_payloads() -> List[Tuple[str, str, bytes]]:
    prefix = VALIDATION_SEED_PREFIX
    out: List[Tuple[str, str, bytes]] = []

    for index in range(VALIDATION_RISKY_PLAN["tls10_client_hello"]):
        seed = f"{prefix}-tls10-{index}"
        out.append(
            (
                "tls10_client_hello",
                seed,
                build_legacy_client_hello_variant(
                    seed, 0x01, _SNI_HOSTS[index % len(_SNI_HOSTS)], _LEGACY_SUITES[: 1 + index % 4]
                ),
            )
        )
    for index in range(VALIDATION_RISKY_PLAN["tls11_client_hello"]):
        seed = f"{prefix}-tls11-{index}"
        out.append(
            (
                "tls11_client_hello",
                seed,
                build_legacy_client_hello_variant(
                    seed, 0x02, _SNI_HOSTS[index % len(_SNI_HOSTS)], _LEGACY_SUITES[: 1 + index % 4]
                ),
            )
        )

    # Weak RSA: 1024-bit keys only — below SP 800-131A's 2048-bit minimum, so
    # RISKY. The existing deterministic 513-bit fixture is deliberately NOT
    # reused here: it IS an observation in the frozen test set, so including it
    # would put a test observation into the calibration cohort. The subject name
    # length varies per observation so the DER, and therefore the payload
    # length, differs between them.
    weak_total = VALIDATION_RISKY_PLAN["weak_rsa_certificate"]
    for index in range(weak_total):
        serial = 1001 + index
        seed = f"{prefix}-weak1024-{serial}"
        common_name = f"{prefix}-weak-{serial}-{'x' * (index + 1)}.invalid"
        out.append(
            (
                "weak_rsa_certificate",
                seed,
                build_certificate_record(1024, 0, serial, common_name),
            )
        )

    methods = ((b"GET", b"/status"), (b"POST", b"/api/v1/session"), (b"GET", b"/metrics"))
    for index in range(VALIDATION_RISKY_PLAN["http_cleartext"]):
        seed = f"{prefix}-http-{index}"
        if index % 2 == 0:
            method, path = methods[index % len(methods)]
            payload = build_http_request_variant(
                seed,
                method,
                path,
                _SNI_HOSTS[index % len(_SNI_HOSTS)],
                trace_length=1 + index,
            )
        else:
            # A per-observation filler field gives each response a distinct
            # length, for the same reason the request carries X-Trace.
            body = (
                b'{"seq":' + str(index).encode("ascii")
                + b',"temp":36.' + str(index % 10).encode("ascii")
                + b',"status":"ok","pad":"' + (b"p" * (1 + index)) + b'"}'
            )
            payload = build_http_response_variant(seed, b"200 OK", body)
        out.append(("http_cleartext", seed, payload))

    # Client identifiers of varying LENGTH, so every CONNECT packet has a
    # distinct payload length. Lengths that would reproduce the frozen test
    # set's own MQTT packet sizes (33 and 36 bytes total, i.e. identifier
    # lengths 17 and 20) are skipped.
    _MQTT_FROZEN_ID_LENGTHS = {17, 20}
    identifier_lengths = [
        length for length in range(8, 26) if length not in _MQTT_FROZEN_ID_LENGTHS
    ]
    for index in range(VALIDATION_RISKY_PLAN["mqtt_no_tls"]):
        seed = f"{prefix}-mqtt-{index}"
        length = identifier_lengths[index % len(identifier_lengths)]
        client_id = (f"p2d-dev-{index:02d}".ljust(length, "z"))[:length].encode("ascii")
        out.append(("mqtt_no_tls", seed, build_mqtt_connect_variant(client_id, 30 + index)))

    # Negotiation bursts of increasing length: observation `index` sends
    # 6 + index option triplets, so payload lengths run 18, 21, 24, ... and are
    # all distinct. They also avoid the frozen test set's own Telnet lengths of
    # 9, 12 and 15 bytes, which is what previously made a validation packet
    # vectorize identically to a test packet.
    _TELNET_COMMANDS = (0xFB, 0xFC, 0xFD, 0xFE)
    _TELNET_OPTIONS = (
        0x01, 0x03, 0x05, 0x06, 0x13, 0x18, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x27, 0x2D, 0x2E,
    )
    for index in range(VALIDATION_RISKY_PLAN["telnet"]):
        seed = f"{prefix}-telnet-{index}"
        triplets = 6 + index
        options: List[int] = []
        for step in range(triplets):
            options.append(_TELNET_COMMANDS[(index + step) % len(_TELNET_COMMANDS)])
            options.append(_TELNET_OPTIONS[(index * 3 + step) % len(_TELNET_OPTIONS)])
        out.append(
            ("telnet", seed, build_telnet_negotiation_variant(tuple(options)))
        )

    return out


def build_validation_observations() -> List[PipelineObservation]:
    """The validation cohort: SAFE and RISKY, never used for model fitting."""
    safe = _validation_safe_payloads()
    risky = _validation_risky_payloads()

    observations: List[PipelineObservation] = []
    for index, (family, seed, payload) in enumerate(safe):
        observations.append(
            PipelineObservation(
                observation_id=seed,
                cohort="validation",
                label=LABEL_SAFE,
                family=family,
                src_ip=_ip_for(index, 20),
                dst_port=443,
                payload=payload,
            )
        )
    port_for = {
        "http_cleartext": 80,
        "mqtt_no_tls": 1883,
        "telnet": 23,
    }
    for index, (family, seed, payload) in enumerate(risky):
        observations.append(
            PipelineObservation(
                observation_id=seed,
                cohort="validation",
                label=LABEL_RISKY,
                family=family,
                src_ip=_ip_for(index, 30),
                dst_port=port_for.get(family, 443),
                payload=payload,
            )
        )
    return observations


def write_cohort_pcap(observations: List[PipelineObservation], path) -> int:
    """Write observations to a pcap so they are read back through the REAL
    production reader (capture.offline_source.OfflinePcapSource)."""
    # Explicit MAC addresses: without them scapy tries to resolve a route for
    # every packet and emits a warning per observation, which buries real output.
    packets = [
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=observation.src_ip, dst="10.0.0.254")
        / TCP(sport=40000 + (index % 20000), dport=observation.dst_port)
        / observation.payload
        for index, observation in enumerate(observations)
    ]
    wrpcap(str(path), packets)
    return len(packets)


def payload_digest(observations: List[PipelineObservation]) -> set:
    """SHA-256 of each payload — used to prove cohort disjointness."""
    return {hashlib.sha256(o.payload).hexdigest() for o in observations}


__all__ = [
    "PipelineObservation",
    "LABEL_SAFE",
    "LABEL_RISKY",
    "TRAIN_PCAP",
    "VALIDATION_PCAP",
    "TRAIN_SEED_PREFIX",
    "VALIDATION_SEED_PREFIX",
    "FROZEN_TEST_SEED_PREFIX",
    "build_training_observations",
    "build_validation_observations",
    "write_cohort_pcap",
    "payload_digest",
    "build_tls13_client_hello_variant",
    "build_tls13_server_hello_variant",
    "build_application_data_record",
    "build_certificate_record",
    "build_legacy_client_hello_variant",
    "build_http_request_variant",
    "build_http_response_variant",
    "build_mqtt_connect_variant",
    "build_telnet_negotiation_variant",
]
