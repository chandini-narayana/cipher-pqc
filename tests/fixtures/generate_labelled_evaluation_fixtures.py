"""Generates tests/fixtures/evaluation_labelled_set.pcap — the Phase 2A
controlled, labelled evaluation dataset (docs/SDD.md's Phase 2A addendum).

Run manually (module form, so the `tests.fixtures` imports resolve):

    python -m tests.fixtures.generate_labelled_evaluation_fixtures

Does NOT modify or replace any existing fixture. sample.pcap,
demo_presentation.pcap and every evaluation_*.pcap from
generate_evaluation_fixtures.py are untouched and still drive the existing
test suite and the Phase 15 harness. This module ADDS one new pcap, and
reuses generate_evaluation_fixtures.py's already-verified payload builders
(_filler, the HTTP request, Telnet negotiation, MQTT CONNECT, the 513-bit
weak-RSA certificate handshake, and the TLS Application Data record)
rather than duplicating them.

WHY A NEW DATASET RATHER THAN AN EXTENSION OF THE OLD ONE. The Phase 15
known-safe set builds its "secure" observation by putting an RFC 7685
`padding` extension into a ServerHello and filling it with high-entropy
bytes. That is not realistic: RFC 7685 defines padding as a ClientHello
extension, its bytes are zero-filled, and a server does not echo it. The
high-entropy filler also lifts the payload's Shannon entropy into the
"no entropy risk" band, which a real ServerHello of that size cannot
reach. Those fixtures remain in place, unchanged, for regression and
continuity — but they are deliberately NOT reused here as the scientific
secure baseline. Every TLS observation below is built the way a real
stack would send it.

DETERMINISM. Every payload is byte-for-byte reproducible via the
SHA-256-chain `_filler` (never os.urandom), with TWO DOCUMENTED
EXCEPTIONS: the RSA-2048 and RSA-3072 certificate observations, whose
keys come from `rsa.generate_private_key()` and therefore differ on every
regeneration. They are included anyway because their measured Shannon
entropy sits far from the nearest scoring boundary (7.0), so their
Quantum Risk Score is stable even though their bytes are not — see
RSA_CERTIFICATE_ENTROPY_FLOOR below and the margin test in
tests/fixtures/test_labelled_evaluation_fixtures.py. Per the approved
Phase 2A decisions, no custom deterministic RSA prime generation is
introduced here, and the RSA-1024 boundary case (measured entropy 6.998,
only 0.002 below the 7.0 boundary) is deliberately OMITTED rather than
reported as an unstable result.

As with every other pcap in this directory, per-packet capture timestamps
are assigned by scapy at write time and vary run to run. No assessment
outcome depends on them: scoring reads payload bytes only.

This module builds packets. It declares NO expected outcome and NO
security label — those live in tests/fixtures/labelled_evaluation_manifest.py,
and are fixed before any packet is ever run through the pipeline.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, List, NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
from scapy.all import IP, TCP, Ether, wrpcap

from tests.fixtures.generate_evaluation_fixtures import (
    _filler,
    build_encrypted_application_data,
    build_high_risk_telnet_negotiation,
    build_mqtt_connect,
    build_plain_http_request,
    build_weak_rsa_certificate_handshake,
)

FIXTURES_DIR = Path(__file__).resolve().parent

LABELLED_SET_PCAP = FIXTURES_DIR / "evaluation_labelled_set.pcap"

# The lowest Shannon entropy (bits/byte) either randomly-keyed RSA
# certificate observation may measure and still be scored as this
# manifest expects. The nearest scoring boundary is 7.0 (entropy_risk
# 1 -> 0); measured values are ~7.42 (RSA-2048) and ~7.60 (RSA-3072), so
# this floor keeps a wide margin while still failing loudly if a future
# `cryptography` release changes certificate encoding enough to matter.
RSA_CERTIFICATE_ENTROPY_FLOOR = 7.15

_TLS_HANDSHAKE_RECORD = 0x16
_CLIENT_HELLO = 0x01
_SERVER_HELLO = 0x02

# Extension type codes (IANA TLS ExtensionType registry).
_EXT_SERVER_NAME = 0x0000
_EXT_STATUS_REQUEST = 0x0005
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_ALPN = 0x0010
_EXT_EXTENDED_MASTER_SECRET = 0x0017
_EXT_PADDING = 0x0015
_EXT_RECORD_SIZE_LIMIT = 0x001C
_EXT_SESSION_TICKET = 0x0023
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_PSK_KEY_EXCHANGE_MODES = 0x002D
_EXT_KEY_SHARE = 0x0033

# NamedGroup code points.
_GROUP_X25519 = 0x001D
_GROUP_SECP256R1 = 0x0017
_GROUP_SECP384R1 = 0x0018
_GROUP_X25519_MLKEM768 = 0x11EC  # RFC 9794-era hybrid PQ key exchange

# Key-share value lengths on the wire.
_X25519_SHARE_LEN = 32
_MLKEM768_CLIENT_SHARE_LEN = 1216  # ML-KEM-768 encapsulation key + X25519
_MLKEM768_SERVER_SHARE_LEN = 1120  # ML-KEM-768 ciphertext + X25519

_TLS13_CIPHER_SUITES = [0x1301, 0x1302, 0x1303]  # AES-128-GCM, AES-256-GCM, CHACHA20
_TLS12_CIPHER_SUITES = [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8]
_LEGACY_CIPHER_SUITES = [0x000A, 0x002F, 0x0035, 0x0005]  # 3DES, AES-CBC, RC4
_SIGNATURE_ALGORITHMS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _extension(ext_type: int, data: bytes) -> bytes:
    return _u16(ext_type) + _u16(len(data)) + data


def _server_name_extension(host: bytes) -> bytes:
    entry = b"\x00" + _u16(len(host)) + host
    return _extension(_EXT_SERVER_NAME, _u16(len(entry)) + entry)


def _supported_groups_extension(groups: List[int]) -> bytes:
    body = _u16(2 * len(groups)) + b"".join(_u16(group) for group in groups)
    return _extension(_EXT_SUPPORTED_GROUPS, body)


def _signature_algorithms_extension() -> bytes:
    body = _u16(2 * len(_SIGNATURE_ALGORITHMS)) + b"".join(
        _u16(algorithm) for algorithm in _SIGNATURE_ALGORITHMS
    )
    return _extension(_EXT_SIGNATURE_ALGORITHMS, body)


def _alpn_extension(protocols: List[bytes]) -> bytes:
    entries = b"".join(bytes([len(name)]) + name for name in protocols)
    return _extension(_EXT_ALPN, _u16(len(entries)) + entries)


def _client_key_share_extension(entries: List[tuple]) -> bytes:
    """`entries` is [(named_group, share_bytes), ...] — a ClientHello
    key_share carries a length-prefixed LIST of offered shares."""
    shares = b"".join(
        _u16(group) + _u16(len(share)) + share for group, share in entries
    )
    return _extension(_EXT_KEY_SHARE, _u16(len(shares)) + shares)


def _server_key_share_extension(named_group: int, share: bytes) -> bytes:
    """A ServerHello key_share carries exactly ONE selected share, with
    no surrounding list length — the real asymmetry in RFC 8446."""
    return _extension(_EXT_KEY_SHARE, _u16(named_group) + _u16(len(share)) + share)


def _handshake_record(handshake_type: int, body: bytes, record_minor: int) -> bytes:
    handshake = bytes([handshake_type]) + len(body).to_bytes(3, "big") + body
    return (
        bytes([_TLS_HANDSHAKE_RECORD, 0x03, record_minor])
        + _u16(len(handshake))
        + handshake
    )


def _cipher_suite_bytes(suites: List[int]) -> bytes:
    return _u16(2 * len(suites)) + b"".join(_u16(suite) for suite in suites)


# --- SECURE: realistic TLS 1.3 -------------------------------------------


def build_tls13_client_hello(
    seed_label: str,
    hybrid_key_share: bool = False,
    pad_to: int = 0,
    server_name: bytes = b"telemetry.hospital.example",
) -> bytes:
    """A realistic TLS 1.3 ClientHello.

    Carries everything a modern client actually sends: a 32-byte
    compatibility session_id, the three TLS 1.3 AEAD cipher suites,
    server_name, supported_groups, signature_algorithms, a real key_share,
    psk_key_exchange_modes, and the `supported_versions` extension (0x002B)
    listing TLS 1.3 first — which is the structure
    fingerprint.tls._highest_client_supported_version() reads to return
    TLSVersion.TLS_1_3 (the legacy client_version field stays pinned at
    {3,3} per RFC 8446, exactly as on the real wire).

    `hybrid_key_share=True` offers X25519MLKEM768 alongside X25519 — the
    post-quantum hybrid key exchange now widely deployed, and the most
    directly relevant "correctly configured, quantum-resistant" secure
    observation this evaluation can contain.

    `pad_to` applies an RFC 7685 `padding` extension CORRECTLY: it is a
    ClientHello extension, and its bytes are ZERO, never high-entropy
    filler. The point of including a padded variant is precisely that
    correct zero padding LOWERS measured Shannon entropy — a realistic,
    properly-configured secure client whose entropy component the frozen
    formula therefore penalizes. That is an honest property of the
    specification under evaluation, not a fixture defect to paper over.
    """
    groups = [_GROUP_X25519, _GROUP_SECP256R1, _GROUP_SECP384R1]
    share_entries = [
        (_GROUP_X25519, _filler(f"{seed_label}-x25519", _X25519_SHARE_LEN))
    ]
    if hybrid_key_share:
        groups = [_GROUP_X25519_MLKEM768] + groups
        share_entries = [
            (
                _GROUP_X25519_MLKEM768,
                _filler(f"{seed_label}-mlkem768", _MLKEM768_CLIENT_SHARE_LEN),
            )
        ] + share_entries

    # A resumption ticket, ALPN, OCSP status_request and record_size_limit
    # are all ordinary parts of a real modern ClientHello. They are
    # included for a substantive reason as well as realism: without them
    # this record is ~218 bytes and its measured Shannon entropy lands
    # within 0.03 of the formula's 6.0 boundary, so otherwise-identical
    # secure configurations would split across two entropy-risk buckets on
    # filler bytes alone. At a realistic ~320 bytes the measurement sits
    # mid-band, and the observation reflects its configuration rather than
    # an accident of payload length.
    extensions = (
        _server_name_extension(server_name)
        + _extension(_EXT_STATUS_REQUEST, bytes([0x01]) + _u16(0) + _u16(0))
        + _supported_groups_extension(groups)
        + _signature_algorithms_extension()
        + _alpn_extension([b"h2", b"http/1.1"])
        + _extension(_EXT_SESSION_TICKET, _filler(f"{seed_label}-ticket", 64))
        + _extension(_EXT_RECORD_SIZE_LIMIT, _u16(16385))
        + _client_key_share_extension(share_entries)
        + _extension(_EXT_SUPPORTED_VERSIONS, bytes([0x04, 0x03, 0x04, 0x03, 0x03]))
        + _extension(_EXT_PSK_KEY_EXCHANGE_MODES, bytes([0x01, 0x01]))
        + _extension(_EXT_EXTENDED_MASTER_SECRET, b"")
    )

    def assemble(extension_bytes: bytes) -> bytes:
        body = (
            bytes([0x03, 0x03])  # legacy_version, pinned per RFC 8446
            + _filler(f"{seed_label}-random", 32)
            + bytes([0x20])
            + _filler(f"{seed_label}-session", 32)  # compatibility session_id
            + _cipher_suite_bytes(_TLS13_CIPHER_SUITES)
            + bytes([0x01, 0x00])  # compression: null only
            + _u16(len(extension_bytes))
            + extension_bytes
        )
        return _handshake_record(_CLIENT_HELLO, body, record_minor=0x01)

    packet = assemble(extensions)
    if pad_to and len(packet) < pad_to:
        padding_length = max(0, pad_to - len(packet) - 4)
        packet = assemble(extensions + _extension(_EXT_PADDING, bytes(padding_length)))
    return packet


def build_tls13_server_hello(
    seed_label: str,
    echo_session_id: bool = True,
    hybrid_key_share: bool = False,
) -> bytes:
    """A realistic TLS 1.3 ServerHello — NO padding extension of any
    kind (RFC 7685 padding is a ClientHello extension and a server never
    echoes it), so its Shannon entropy is whatever a real ServerHello of
    this size genuinely measures.

    The negotiated version appears ONLY in the 2-byte
    `supported_versions` extension, which is what
    fingerprint.tls._selected_server_supported_version() reads; the
    legacy server_version field stays at {3,3}.

    `hybrid_key_share=True` returns an X25519MLKEM768 ciphertext, which
    makes the record ~1.1 kB — realistic for post-quantum hybrid key
    exchange, and large enough that measured entropy clears the formula's
    7.0 boundary without any artificial padding.

    `echo_session_id=False` produces the minimal, compatibility-mode-off
    ServerHello a TLS-1.3-only peer may send. It is small, so its
    measured entropy is genuinely low — retained deliberately as a
    realistic secure observation that the entropy component penalizes.
    """
    if hybrid_key_share:
        key_share = _server_key_share_extension(
            _GROUP_X25519_MLKEM768,
            _filler(f"{seed_label}-mlkem768-ct", _MLKEM768_SERVER_SHARE_LEN),
        )
    else:
        key_share = _server_key_share_extension(
            _GROUP_X25519, _filler(f"{seed_label}-x25519", _X25519_SHARE_LEN)
        )

    extensions = (
        _extension(_EXT_SUPPORTED_VERSIONS, bytes([0x03, 0x04])) + key_share
    )

    session_id = (
        bytes([0x20]) + _filler(f"{seed_label}-session", 32)
        if echo_session_id
        else bytes([0x00])
    )
    body = (
        bytes([0x03, 0x03])  # legacy_version, pinned per RFC 8446
        + _filler(f"{seed_label}-random", 32)
        + session_id
        + _u16(_TLS13_CIPHER_SUITES[0])
        + bytes([0x00])  # compression_method: null
        + _u16(len(extensions))
        + extensions
    )
    return _handshake_record(_SERVER_HELLO, body, record_minor=0x03)


# --- MODERATE / HIGH RISK: legacy TLS ------------------------------------


def build_legacy_client_hello(
    seed_label: str,
    record_minor: int,
    server_name: bytes = b"legacy-device.hospital.example",
) -> bytes:
    """A realistic pre-1.3 ClientHello for TLS 1.0 ({3,1}), 1.1 ({3,2})
    or 1.2 ({3,3}), selected by `record_minor`.

    Sends NO `supported_versions` extension — correct, since that
    extension is TLS 1.3-only — so fingerprint.tls.detect_tls_version()
    reads the legacy client_version field, exactly as it must for a real
    legacy handshake. TLS 1.2 offers modern AEAD suites; TLS 1.0/1.1 offer
    the obsolete suites (3DES/CBC/RC4) real clients of that era sent.
    """
    if record_minor == 0x03:
        suites = _TLS12_CIPHER_SUITES
    else:
        suites = _LEGACY_CIPHER_SUITES

    extensions = (
        _server_name_extension(server_name)
        + _supported_groups_extension([_GROUP_X25519, _GROUP_SECP256R1])
        + _signature_algorithms_extension()
    )
    body = (
        bytes([0x03, record_minor])
        + _filler(f"{seed_label}-random", 32)
        + bytes([0x00])  # session_id_len = 0
        + _cipher_suite_bytes(suites)
        + bytes([0x01, 0x00])  # compression: null only
        + _u16(len(extensions))
        + extensions
    )
    return _handshake_record(_CLIENT_HELLO, body, record_minor=record_minor)


# --- MODERATE: acceptable-key-size RSA certificates ----------------------


def build_rsa_certificate_handshake(key_size_bits: int) -> bytes:
    """A real TLS Certificate handshake message carrying a genuine,
    self-signed X.509 certificate with an RSA key of `key_size_bits`,
    parsed for real by fingerprint.tls.extract_rsa_key_size().

    NOT byte-reproducible: `rsa.generate_private_key()` is random, so
    the certificate (and this packet) differ on every regeneration. This
    is an accepted, documented exception (see module docstring) — the
    approved Phase 2A decisions rule out adding custom deterministic
    prime generation, and these observations exist to exercise the
    key-size scoring buckets at >=2048 bits, where the measured entropy
    margin to the nearest boundary is wide enough that the score is
    stable regardless of the specific key.

    The 513-bit weak-key case is NOT built here: it already exists as a
    fully deterministic fixture
    (generate_evaluation_fixtures.build_weak_rsa_certificate_handshake),
    which this dataset reuses unchanged.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size_bits)
    name = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME, f"cipher-eval-rsa{key_size_bits}.invalid"
            )
        ]
    )
    not_before = datetime(2020, 1, 1, tzinfo=timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_before + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )
    cert_der = certificate.public_bytes(serialization.Encoding.DER)

    certificate_list = len(cert_der).to_bytes(3, "big") + cert_der
    body = len(certificate_list).to_bytes(3, "big") + certificate_list
    return _handshake_record(0x0B, body, record_minor=0x03)  # 0x0B = Certificate


# --- MODERATE: cleartext application protocols ---------------------------


def build_http_response() -> bytes:
    """A real, plaintext HTTP/1.1 response carrying device telemetry —
    recognized by fingerprint.protocol._looks_like_http() via its
    `HTTP/1.` status line."""
    payload = (
        b'{"device":"infusion-pump-07","status":"ok","battery_pct":88,'
        b'"firmware":"2.4.1","alarms":[],"rate_ml_h":12.5,'
        b'"observed_at":"2026-09-30T10:00:00Z","sequence":1042}'
    )
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Server: cipher-eval-device/1.0\r\n"
        b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
        b"\r\n" + payload
    )


def build_http_post_request() -> bytes:
    """A real, plaintext HTTP/1.1 POST — credentials in cleartext, the
    canonical cleartext-management-interface observation."""
    payload = b'{"username":"clinician","password":"cipher-eval-placeholder"}'
    return (
        b"POST /api/v1/session HTTP/1.1\r\n"
        b"Host: infusion-pump-07.hospital.example\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n"
        b"\r\n" + payload
    )


def build_telnet_negotiation_variant(variant: int) -> bytes:
    """Additional real Telnet option-negotiation bursts, in the same
    IAC/WILL/WONT/DO/DONT wire form as
    generate_evaluation_fixtures.build_high_risk_telnet_negotiation()
    (which this dataset also reuses unchanged), so the Telnet
    observations are genuinely distinct packets rather than one repeated.
    """
    variants = {
        1: [
            0xFF, 0xFD, 0x01,  # IAC DO ECHO
            0xFF, 0xFB, 0x03,  # IAC WILL SUPPRESS-GO-AHEAD
            0xFF, 0xFE, 0x22,  # IAC DONT LINEMODE
        ],
        2: [
            0xFF, 0xFB, 0x18,  # IAC WILL TERMINAL-TYPE
            0xFF, 0xFB, 0x1F,  # IAC WILL NAWS
            0xFF, 0xFD, 0x20,  # IAC DO TERMINAL-SPEED
            0xFF, 0xFD, 0x23,  # IAC DO X-DISPLAY-LOCATION
            0xFF, 0xFC, 0x25,  # IAC WONT AUTHENTICATION
        ],
    }
    if variant not in variants:
        raise ValueError(f"unknown telnet variant {variant}; expected one of {sorted(variants)}")
    return bytes(variants[variant])


# --- INDETERMINATE -------------------------------------------------------


def build_opaque_payload(seed_label: str, length: int = 160) -> bytes:
    """An opaque, non-signature-matching payload: classified
    ProtocolType.OTHER because it deliberately matches none of the four
    specific detectors (its first byte is not a TLS content type, not an
    HTTP method/status line, not MQTT's 0x10, not Telnet's 0xFF).

    Represents the genuinely common case of traffic a passive,
    payload-only fingerprinter cannot attribute to any known protocol —
    which is exactly why its external security label is EXCLUDED rather
    than SAFE or RISKY.
    """
    return bytes([0x00, 0x01]) + _filler(f"{seed_label}-opaque", length - 2)


# --- observation registry ------------------------------------------------


class LabelledPacketSpec(NamedTuple):
    """One observation's PACKET definition — its identity, address and
    payload builder ONLY.

    Carries no expected score and no security label by design: ground
    truth lives in tests/fixtures/labelled_evaluation_manifest.py, is
    declared independently of anything this module produces, and is
    matched to these packets by `scenario_id` (a test asserts the two id
    sets are exactly equal).
    """

    scenario_id: str
    src_ip: str
    dst_port: int
    build_payload: Callable[[], bytes]


# `src_ip` is each observation's stable join key between this generator,
# the manifest and evaluate_research.py — pipeline.runner identifies a
# device by RawPacket.src_ip, so one unique address per observation keeps
# every packet an independently-addressed device and makes the mapping
# order-independent (never a fragile packet index).
LABELLED_PACKET_SPECS: List[LabelledPacketSpec] = [
    # --- SECURE: realistic TLS 1.3 ---------------------------------------
    LabelledPacketSpec("tls13_client_hello_x25519_a", "192.168.40.11", 443,
                       lambda: build_tls13_client_hello("labelled-ch-a")),
    LabelledPacketSpec("tls13_client_hello_x25519_b", "192.168.40.12", 443,
                       lambda: build_tls13_client_hello("labelled-ch-b")),
    LabelledPacketSpec("tls13_client_hello_x25519_c", "192.168.40.13", 443,
                       lambda: build_tls13_client_hello("labelled-ch-c")),
    LabelledPacketSpec("tls13_client_hello_hybrid_pq_a", "192.168.40.14", 443,
                       lambda: build_tls13_client_hello("labelled-pq-a", hybrid_key_share=True)),
    LabelledPacketSpec("tls13_client_hello_hybrid_pq_b", "192.168.40.15", 443,
                       lambda: build_tls13_client_hello("labelled-pq-b", hybrid_key_share=True)),
    LabelledPacketSpec("tls13_client_hello_zero_padded_a", "192.168.40.16", 443,
                       lambda: build_tls13_client_hello("labelled-pad-a", pad_to=512)),
    LabelledPacketSpec("tls13_client_hello_zero_padded_b", "192.168.40.17", 443,
                       lambda: build_tls13_client_hello("labelled-pad-b", pad_to=768)),
    LabelledPacketSpec("tls13_server_hello_x25519_a", "192.168.40.18", 443,
                       lambda: build_tls13_server_hello("labelled-sh-a")),
    LabelledPacketSpec("tls13_server_hello_x25519_b", "192.168.40.19", 443,
                       lambda: build_tls13_server_hello("labelled-sh-b")),
    LabelledPacketSpec("tls13_server_hello_minimal", "192.168.40.20", 443,
                       lambda: build_tls13_server_hello("labelled-sh-min", echo_session_id=False)),
    LabelledPacketSpec("tls13_server_hello_hybrid_pq", "192.168.40.21", 443,
                       lambda: build_tls13_server_hello("labelled-sh-pq", hybrid_key_share=True)),
    # --- MODERATE: TLS 1.2 (externally EXCLUDED — see manifest) ----------
    LabelledPacketSpec("tls12_client_hello_a", "192.168.40.31", 443,
                       lambda: build_legacy_client_hello("labelled-tls12-a", 0x03)),
    LabelledPacketSpec("tls12_client_hello_b", "192.168.40.32", 443,
                       lambda: build_legacy_client_hello("labelled-tls12-b", 0x03)),
    # --- MODERATE: acceptable RSA key sizes (EXCLUDED — see manifest) ----
    LabelledPacketSpec("rsa2048_certificate", "192.168.40.33", 443,
                       lambda: build_rsa_certificate_handshake(2048)),
    LabelledPacketSpec("rsa3072_certificate", "192.168.40.34", 443,
                       lambda: build_rsa_certificate_handshake(3072)),
    # --- MODERATE: cleartext application protocols (RISKY) ---------------
    LabelledPacketSpec("http_get_cleartext", "192.168.40.41", 80,
                       build_plain_http_request),
    LabelledPacketSpec("http_response_cleartext", "192.168.40.42", 80,
                       build_http_response),
    LabelledPacketSpec("http_post_credentials_cleartext", "192.168.40.43", 80,
                       build_http_post_request),
    LabelledPacketSpec("mqtt_connect_no_tls_a", "192.168.40.44", 1883,
                       lambda: build_mqtt_connect(b"cipher-eval-pump-01")),
    LabelledPacketSpec("mqtt_connect_no_tls_b", "192.168.40.45", 1883,
                       lambda: build_mqtt_connect(b"cipher-eval-monitor-02")),
    # --- HIGH RISK: deprecated TLS, weak key, cleartext shell ------------
    LabelledPacketSpec("tls10_client_hello_a", "192.168.40.51", 443,
                       lambda: build_legacy_client_hello("labelled-tls10-a", 0x01)),
    LabelledPacketSpec("tls10_client_hello_b", "192.168.40.52", 443,
                       lambda: build_legacy_client_hello("labelled-tls10-b", 0x01)),
    LabelledPacketSpec("tls11_client_hello_a", "192.168.40.53", 443,
                       lambda: build_legacy_client_hello("labelled-tls11-a", 0x02)),
    LabelledPacketSpec("tls11_client_hello_b", "192.168.40.54", 443,
                       lambda: build_legacy_client_hello("labelled-tls11-b", 0x02)),
    LabelledPacketSpec("rsa513_weak_certificate", "192.168.40.55", 443,
                       build_weak_rsa_certificate_handshake),
    LabelledPacketSpec("telnet_negotiation_a", "192.168.40.56", 23,
                       build_high_risk_telnet_negotiation),
    LabelledPacketSpec("telnet_negotiation_b", "192.168.40.57", 23,
                       lambda: build_telnet_negotiation_variant(1)),
    LabelledPacketSpec("telnet_negotiation_c", "192.168.40.58", 23,
                       lambda: build_telnet_negotiation_variant(2)),
    # --- INDETERMINATE ---------------------------------------------------
    LabelledPacketSpec("tls_encrypted_application_data", "192.168.40.61", 443,
                       build_encrypted_application_data),
    LabelledPacketSpec("opaque_unclassified_payload", "192.168.40.62", 9000,
                       lambda: build_opaque_payload("labelled-opaque")),
]

LABELLED_SET_SIZE = len(LABELLED_PACKET_SPECS)


def build_labelled_packets() -> list:
    """Build every labelled observation as a scapy packet, in
    LABELLED_PACKET_SPECS order."""
    return [
        Ether()
        / IP(src=spec.src_ip, dst="192.168.40.254")
        / TCP(sport=50000 + index, dport=spec.dst_port)
        / spec.build_payload()
        for index, spec in enumerate(LABELLED_PACKET_SPECS)
    ]


def main() -> None:
    wrpcap(str(LABELLED_SET_PCAP), build_labelled_packets())
    print(f"Wrote {LABELLED_SET_SIZE} labelled observations to {LABELLED_SET_PCAP}")


if __name__ == "__main__":
    main()
