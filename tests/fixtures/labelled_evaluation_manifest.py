"""Ground truth for the Phase 2A controlled labelled evaluation dataset
(docs/SDD.md's Phase 2A addendum).

This module stores DECLARED EXPECTATIONS AND LABELS ONLY. It contains no
scoring, fingerprinting, entropy, fusion, or enforcement logic, imports
none of risk/, fingerprint/, entropy/, fusion/, ml/ or enforcement/, and
must never be treated as the source of truth for what CIPHER computes —
only for what CIPHER is SPECIFIED to compute, and for what an external
security rubric says about each observation.

TWO INDEPENDENT KINDS OF GROUND TRUTH, DELIBERATELY KEPT SEPARATE:

1. `qrs_expected_*` — the Quantum Risk Score the FROZEN published formula
   must produce for this observation, plus its per-component breakdown,
   category and isolation eligibility. Every value was derived by applying
   the published formula (docs/SDD.md; risk/scoring.py's documented
   tables) by hand to the observation's known construction. Measuring
   these against the real engine tests IMPLEMENTATION CONFORMANCE to a
   specification — it is never a measure of detection accuracy, and it is
   deliberately not evidence that the specification itself is correct.

2. `external_security_label` — SAFE / RISKY / EXCLUDED, assigned from the
   a-priori external rubric below. THIS IS NEVER DERIVED FROM CIPHER'S
   OUTPUT: not from the actual Quantum Risk Score, not from the expected
   one, not from a risk category, not from a fused final category, and not
   from any anomaly signal. It is fixed by published standards before any
   packet is executed. That independence is the whole point: labelling
   observations by the score under evaluation would make the resulting
   metrics circular and worthless.

THE EXTERNAL SECURITY RUBRIC (a-priori, standards-based):

  RISKY:
  - TLS 1.0 and TLS 1.1 — formally deprecated by RFC 8996; prohibited for
    government use by NIST SP 800-52r2.
  - RSA keys below 2048 bits — disallowed by NIST SP 800-131A Rev. 2.
  - Cleartext HTTP — no confidentiality or integrity for the session;
    SP 800-52r2 requires TLS for protected information.
  - MQTT without TLS — same cleartext exposure, on a protocol whose
    CONNECT frame carries credentials in the clear.
  - Telnet — cleartext interactive remote shell, including authentication.

  SAFE:
  - TLS 1.3 (RFC 8446) as actually configured on the wire: AEAD-only
    cipher suites, ephemeral key establishment, no deprecated primitive
    offered. The hybrid X25519MLKEM768 variants additionally provide
    quantum-resistant key establishment, which is the strongest
    configuration this dataset contains.

  EXCLUDED (retained for Quantum Risk Score conformance, omitted from
  every binary security-classification metric):
  - TLS 1.2. SP 800-52r2 PERMITS TLS 1.2 when it is configured with
    approved cipher suites, so the version alone does not settle the
    question, and a single passively captured handshake packet does not
    establish which suite will actually be negotiated. Forcing a binary
    label here would mean inventing ground truth the external standards
    do not supply for an isolated packet — so it is excluded and the
    reason recorded, rather than labelled to whichever value would make
    the metrics look better.
  - Certificate observations with RSA >= 2048 bits. The key length is
    acceptable under SP 800-131A, so the observation is not RISKY on
    key-strength grounds; but a TLS Certificate message carries no
    protocol-version field, so the surrounding configuration is
    undetermined from this packet alone. Kept because they are the only
    observations exercising the >= 2048-bit key-size scoring buckets.
  - Encrypted TLS Application Data, and opaque payloads matching no
    protocol signature. Neither carries version, suite or key evidence, so
    no standards-based judgment about the endpoint's configuration is
    possible from the packet. Their presence is realistic and their
    Quantum Risk Score behavior is worth reporting, but they cannot
    honestly be called safe or risky.

  Deliberately NOT part of the rubric: forward secrecy. Every observation
  would be labelled identically on that axis, because
  fingerprint.protocol.fingerprint_packet() always reports
  forward_secrecy=False (confirming it requires cipher-suite
  classification, outside the frozen fingerprinter's scope). It is
  therefore a constant, not a discriminating criterion, and is reported as
  a known limitation rather than used as a label.

THE ENTROPY COMPONENT IS A MEASURED PROPERTY, NOT A DESIGNED ONE. Each
`qrs_expected_entropy_risk` below states the bucket the observation's
payload bytes actually fall in. Every payload is byte-for-byte
deterministic (two documented RSA exceptions — see
generate_labelled_evaluation_fixtures.py), so these are reproducible
constants, and every one sits clear of a bucket boundary: the narrowest
margin in the set is 0.14 bits/byte. They are declared here so that a
change in the entropy engine, the fingerprinter or a payload builder
fails loudly with a named observation instead of silently shifting a
reported metric.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from models.enums import ProtocolType, RiskCategory
from tests.fixtures.generate_labelled_evaluation_fixtures import (
    LABELLED_SET_PCAP,
    LABELLED_SET_SIZE,
)

# --- scenario groups (descriptive strata, never used as labels) ----------

GROUP_SECURE = "secure"
GROUP_MODERATE = "moderate-risk"
GROUP_HIGH = "high-risk"
GROUP_INDETERMINATE = "indeterminate"

GROUPS = (GROUP_SECURE, GROUP_MODERATE, GROUP_HIGH, GROUP_INDETERMINATE)

# --- external security labels (a-priori, standards-based) ----------------

LABEL_SAFE = "SAFE"
LABEL_RISKY = "RISKY"
LABEL_EXCLUDED = "EXCLUDED"

EXTERNAL_LABELS = (LABEL_SAFE, LABEL_RISKY, LABEL_EXCLUDED)

# Labels that participate in binary security-classification metrics.
# EXCLUDED observations are carried through Quantum Risk Score conformance
# reporting and then dropped from every confusion matrix.
BINARY_LABELS = (LABEL_SAFE, LABEL_RISKY)

LABELLED_SET_PCAP_PATH = LABELLED_SET_PCAP

EXTERNAL_RUBRIC_CITATIONS = (
    "RFC 8996 (deprecating TLS 1.0/1.1)",
    "RFC 8446 (TLS 1.3)",
    "NIST SP 800-52r2 (TLS configuration guidance)",
    "NIST SP 800-131A Rev. 2 (RSA >= 2048 bits)",
)


@dataclass(frozen=True)
class LabelledObservation:
    """One controlled observation's declared ground truth.

    `src_ip` is the join key to the generated packet (see
    generate_labelled_evaluation_fixtures.LabelledPacketSpec) — never a
    packet index, so neither file's ordering can silently desynchronize
    the other's expectations.

    Raises:
        ValueError: on internally inconsistent declared data — an unknown
            group or label, a component breakdown that does not sum to the
            declared total, an out-of-range total, or an isolation
            expectation that contradicts the declared total. These are
            self-consistency checks over values declared IN THIS FILE.
            They re-implement no scoring: the arithmetic identity being
            checked is the published formula's own shape, and the real
            engine's agreement with these declarations is measured
            separately, against the real pipeline, in
            tests/fixtures/test_labelled_evaluation_fixtures.py.
    """

    scenario_id: str
    src_ip: str
    group: str
    description: str

    expected_protocol: ProtocolType
    qrs_expected_tls_risk: int
    qrs_expected_key_size_risk: int
    qrs_expected_pfs_risk: int
    qrs_expected_entropy_risk: int
    qrs_expected_port_risk: int
    qrs_expected_total: int
    qrs_expected_category: RiskCategory
    qrs_expected_isolation_eligible: bool

    external_security_label: str
    security_rationale: str

    # The frozen isolation threshold this dataset's eligibility
    # expectations were written against (config.constants
    # .DEFAULT_RISK_ISOLATION_THRESHOLD). Declared, never imported from
    # config/, so this manifest stays free of runtime imports; a test
    # asserts the two agree.
    ISOLATION_THRESHOLD: int = 7

    def __post_init__(self) -> None:
        if self.group not in GROUPS:
            raise ValueError(
                f"{self.scenario_id}: unknown group {self.group!r}; expected one of {GROUPS}"
            )
        if self.external_security_label not in EXTERNAL_LABELS:
            raise ValueError(
                f"{self.scenario_id}: unknown external_security_label "
                f"{self.external_security_label!r}; expected one of {EXTERNAL_LABELS}"
            )
        if not self.security_rationale.strip():
            raise ValueError(f"{self.scenario_id}: security_rationale must not be empty")

        component_sum = (
            self.qrs_expected_tls_risk
            + self.qrs_expected_key_size_risk
            + self.qrs_expected_pfs_risk
            + self.qrs_expected_entropy_risk
            + self.qrs_expected_port_risk
        )
        if component_sum != self.qrs_expected_total:
            raise ValueError(
                f"{self.scenario_id}: declared components sum to {component_sum} "
                f"but qrs_expected_total is {self.qrs_expected_total}. (No observation "
                f"in this dataset reaches the formula's cap of 10, so the sum must "
                f"match exactly; a capped observation would need this check revisited "
                f"deliberately rather than loosened.)"
            )
        if not 0 <= self.qrs_expected_total <= 10:
            raise ValueError(
                f"{self.scenario_id}: qrs_expected_total {self.qrs_expected_total} "
                f"is outside the formula's [0, 10] range"
            )

        expected_eligible = self.qrs_expected_total >= self.ISOLATION_THRESHOLD
        if expected_eligible != self.qrs_expected_isolation_eligible:
            raise ValueError(
                f"{self.scenario_id}: qrs_expected_isolation_eligible is "
                f"{self.qrs_expected_isolation_eligible}, but a declared total of "
                f"{self.qrs_expected_total} against threshold "
                f"{self.ISOLATION_THRESHOLD} implies {expected_eligible}"
            )

    @property
    def participates_in_binary_metrics(self) -> bool:
        return self.external_security_label in BINARY_LABELS

    @property
    def is_externally_risky(self) -> bool:
        """The positive class for binary security classification.

        Raises:
            ValueError: if called on an EXCLUDED observation — there is no
                binary truth value to return, and defaulting to False
                would silently count it as a safe observation.
        """
        if not self.participates_in_binary_metrics:
            raise ValueError(
                f"{self.scenario_id} is {self.external_security_label}; it has no "
                f"binary security label (see this module's rubric)"
            )
        return self.external_security_label == LABEL_RISKY


_TLS13_SAFE_RATIONALE = (
    "TLS 1.3 (RFC 8446) offering AEAD-only cipher suites with ephemeral key "
    "establishment and no deprecated primitive; SP 800-52r2 permits and prefers "
    "TLS 1.3."
)
_TLS13_PQ_SAFE_RATIONALE = (
    "TLS 1.3 (RFC 8446) with hybrid X25519MLKEM768 key establishment — AEAD-only "
    "suites plus quantum-resistant key exchange, the strongest configuration in "
    "this dataset."
)
_TLS12_EXCLUDED_RATIONALE = (
    "SP 800-52r2 permits TLS 1.2 when configured with approved cipher suites, so "
    "the version alone does not determine safety, and one passively captured "
    "handshake packet does not establish the suite that will be negotiated. No "
    "clean a-priori binary label exists; retained for QRS conformance only."
)
_RSA_STRONG_EXCLUDED_RATIONALE = (
    "Key length is acceptable under SP 800-131A Rev. 2 (>= 2048 bits), so this is "
    "not RISKY on key-strength grounds, but a TLS Certificate message carries no "
    "protocol-version field, leaving the surrounding configuration undetermined. "
    "Retained because it is one of only two observations exercising the "
    ">= 2048-bit key-size buckets."
)


LABELLED_OBSERVATIONS: List[LabelledObservation] = [
    # --- SECURE (realistic TLS 1.3; no artificial high-entropy padding) ---
    LabelledObservation(
        scenario_id="tls13_client_hello_x25519_a",
        src_ip="192.168.40.11",
        group=GROUP_SECURE,
        description="Realistic TLS 1.3 ClientHello, X25519 key share, ALPN h2, resumption ticket.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=1,
        qrs_expected_port_risk=0,
        qrs_expected_total=2,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_SAFE_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls13_client_hello_x25519_b",
        src_ip="192.168.40.12",
        group=GROUP_SECURE,
        description="Realistic TLS 1.3 ClientHello, X25519 key share, independent seed.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=1,
        qrs_expected_port_risk=0,
        qrs_expected_total=2,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_SAFE_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls13_client_hello_x25519_c",
        src_ip="192.168.40.13",
        group=GROUP_SECURE,
        description="Realistic TLS 1.3 ClientHello, X25519 key share, independent seed.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=1,
        qrs_expected_port_risk=0,
        qrs_expected_total=2,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_SAFE_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls13_client_hello_hybrid_pq_a",
        src_ip="192.168.40.14",
        group=GROUP_SECURE,
        description="TLS 1.3 ClientHello offering hybrid post-quantum X25519MLKEM768 key share.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=0,
        qrs_expected_port_risk=0,
        qrs_expected_total=1,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_PQ_SAFE_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls13_client_hello_hybrid_pq_b",
        src_ip="192.168.40.15",
        group=GROUP_SECURE,
        description="TLS 1.3 ClientHello, hybrid post-quantum key share, independent seed.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=0,
        qrs_expected_port_risk=0,
        qrs_expected_total=1,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_PQ_SAFE_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls13_client_hello_zero_padded_a",
        src_ip="192.168.40.16",
        group=GROUP_SECURE,
        description=(
            "TLS 1.3 ClientHello padded to 512 bytes with a correctly zero-filled "
            "RFC 7685 padding extension."
        ),
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=3,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=(
            _TLS13_SAFE_RATIONALE
            + " RFC 7685 padding is zero-filled by specification, which lowers measured "
            "payload entropy; the configuration is unaffected, so the external label "
            "remains SAFE regardless of how the entropy component scores it."
        ),
    ),
    LabelledObservation(
        scenario_id="tls13_client_hello_zero_padded_b",
        src_ip="192.168.40.17",
        group=GROUP_SECURE,
        description="TLS 1.3 ClientHello zero-padded to 768 bytes per RFC 7685.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=3,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=(
            _TLS13_SAFE_RATIONALE
            + " Correct zero-filled RFC 7685 padding; a larger pad lowers measured "
            "entropy further without changing the negotiated configuration."
        ),
    ),
    LabelledObservation(
        scenario_id="tls13_server_hello_x25519_a",
        src_ip="192.168.40.18",
        group=GROUP_SECURE,
        description=(
            "Realistic TLS 1.3 ServerHello selecting X25519 and AES-128-GCM, with "
            "no padding extension (a server never echoes RFC 7685 padding)."
        ),
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=1,
        qrs_expected_port_risk=0,
        qrs_expected_total=2,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_SAFE_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls13_server_hello_x25519_b",
        src_ip="192.168.40.19",
        group=GROUP_SECURE,
        description="Realistic TLS 1.3 ServerHello, X25519, independent seed.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=1,
        qrs_expected_port_risk=0,
        qrs_expected_total=2,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_SAFE_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls13_server_hello_minimal",
        src_ip="192.168.40.20",
        group=GROUP_SECURE,
        description=(
            "Minimal TLS 1.3 ServerHello with no compatibility session_id — the "
            "smallest realistic form, and therefore genuinely low-entropy."
        ),
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=3,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=(
            _TLS13_SAFE_RATIONALE
            + " Its low measured entropy is a consequence of the record being short, "
            "not of any weakness in the configuration."
        ),
    ),
    LabelledObservation(
        scenario_id="tls13_server_hello_hybrid_pq",
        src_ip="192.168.40.21",
        group=GROUP_SECURE,
        description="TLS 1.3 ServerHello returning a hybrid X25519MLKEM768 key share.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=0,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=0,
        qrs_expected_port_risk=0,
        qrs_expected_total=1,
        qrs_expected_category=RiskCategory.LOW,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_SAFE,
        security_rationale=_TLS13_PQ_SAFE_RATIONALE,
    ),
    # --- MODERATE: TLS 1.2 (externally EXCLUDED) --------------------------
    LabelledObservation(
        scenario_id="tls12_client_hello_a",
        src_ip="192.168.40.31",
        group=GROUP_MODERATE,
        description="TLS 1.2 ClientHello offering modern AEAD suites, no supported_versions.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=1,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=4,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_EXCLUDED,
        security_rationale=_TLS12_EXCLUDED_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="tls12_client_hello_b",
        src_ip="192.168.40.32",
        group=GROUP_MODERATE,
        description="TLS 1.2 ClientHello, modern AEAD suites, independent seed.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=1,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=4,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_EXCLUDED,
        security_rationale=_TLS12_EXCLUDED_RATIONALE,
    ),
    # --- MODERATE: acceptable RSA key sizes (externally EXCLUDED) ---------
    LabelledObservation(
        scenario_id="rsa2048_certificate",
        src_ip="192.168.40.33",
        group=GROUP_MODERATE,
        description="TLS Certificate handshake message carrying a real 2048-bit RSA certificate.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=2,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=0,
        qrs_expected_port_risk=0,
        qrs_expected_total=5,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_EXCLUDED,
        security_rationale=_RSA_STRONG_EXCLUDED_RATIONALE,
    ),
    LabelledObservation(
        scenario_id="rsa3072_certificate",
        src_ip="192.168.40.34",
        group=GROUP_MODERATE,
        description="TLS Certificate handshake message carrying a real 3072-bit RSA certificate.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=0,
        qrs_expected_port_risk=0,
        qrs_expected_total=3,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_EXCLUDED,
        security_rationale=_RSA_STRONG_EXCLUDED_RATIONALE,
    ),
    # --- MODERATE: cleartext application protocols (RISKY) ----------------
    LabelledObservation(
        scenario_id="http_get_cleartext",
        src_ip="192.168.40.41",
        group=GROUP_MODERATE,
        description="Plaintext HTTP/1.1 GET request to a device status endpoint.",
        expected_protocol=ProtocolType.HTTP,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=1,
        qrs_expected_total=6,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "Cleartext HTTP provides no confidentiality or integrity; SP 800-52r2 "
            "requires TLS for protected information."
        ),
    ),
    LabelledObservation(
        scenario_id="http_response_cleartext",
        src_ip="192.168.40.42",
        group=GROUP_MODERATE,
        description="Plaintext HTTP/1.1 200 response carrying device telemetry.",
        expected_protocol=ProtocolType.HTTP,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=1,
        qrs_expected_total=6,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "Cleartext HTTP response exposing device telemetry; no confidentiality "
            "or integrity protection (SP 800-52r2)."
        ),
    ),
    LabelledObservation(
        scenario_id="http_post_credentials_cleartext",
        src_ip="192.168.40.43",
        group=GROUP_MODERATE,
        description="Plaintext HTTP/1.1 POST submitting credentials in the clear.",
        expected_protocol=ProtocolType.HTTP,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=1,
        qrs_expected_total=6,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "Cleartext HTTP carrying authentication credentials — no confidentiality "
            "for a secret that grants device access (SP 800-52r2)."
        ),
    ),
    LabelledObservation(
        scenario_id="mqtt_connect_no_tls_a",
        src_ip="192.168.40.44",
        group=GROUP_MODERATE,
        description="MQTT 3.1.1 CONNECT packet with no TLS layer.",
        expected_protocol=ProtocolType.MQTT,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=1,
        qrs_expected_total=6,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "MQTT without TLS transmits its CONNECT frame, including any credentials, "
            "in the clear."
        ),
    ),
    LabelledObservation(
        scenario_id="mqtt_connect_no_tls_b",
        src_ip="192.168.40.45",
        group=GROUP_MODERATE,
        description="MQTT 3.1.1 CONNECT packet, different client identifier, no TLS.",
        expected_protocol=ProtocolType.MQTT,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=1,
        qrs_expected_total=6,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "MQTT without TLS transmits its CONNECT frame, including any credentials, "
            "in the clear."
        ),
    ),
    # --- HIGH RISK -------------------------------------------------------
    LabelledObservation(
        scenario_id="tls10_client_hello_a",
        src_ip="192.168.40.51",
        group=GROUP_HIGH,
        description="TLS 1.0 ClientHello offering 3DES/CBC/RC4-era cipher suites.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=4,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=7,
        qrs_expected_category=RiskCategory.HIGH,
        qrs_expected_isolation_eligible=True,
        external_security_label=LABEL_RISKY,
        security_rationale="TLS 1.0 is deprecated by RFC 8996 and prohibited by SP 800-52r2.",
    ),
    LabelledObservation(
        scenario_id="tls10_client_hello_b",
        src_ip="192.168.40.52",
        group=GROUP_HIGH,
        description="TLS 1.0 ClientHello, independent seed.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=4,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=7,
        qrs_expected_category=RiskCategory.HIGH,
        qrs_expected_isolation_eligible=True,
        external_security_label=LABEL_RISKY,
        security_rationale="TLS 1.0 is deprecated by RFC 8996 and prohibited by SP 800-52r2.",
    ),
    LabelledObservation(
        scenario_id="tls11_client_hello_a",
        src_ip="192.168.40.53",
        group=GROUP_HIGH,
        description="TLS 1.1 ClientHello offering 3DES/CBC/RC4-era cipher suites.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=3,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=6,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_RISKY,
        security_rationale="TLS 1.1 is deprecated by RFC 8996 and prohibited by SP 800-52r2.",
    ),
    LabelledObservation(
        scenario_id="tls11_client_hello_b",
        src_ip="192.168.40.54",
        group=GROUP_HIGH,
        description="TLS 1.1 ClientHello, independent seed.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=3,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=6,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_RISKY,
        security_rationale="TLS 1.1 is deprecated by RFC 8996 and prohibited by SP 800-52r2.",
    ),
    LabelledObservation(
        scenario_id="rsa513_weak_certificate",
        src_ip="192.168.40.55",
        group=GROUP_HIGH,
        description=(
            "TLS Certificate handshake message carrying the existing deterministic "
            "513-bit RSA certificate fixture, reused unchanged."
        ),
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=4,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=0,
        qrs_expected_total=9,
        qrs_expected_category=RiskCategory.HIGH,
        qrs_expected_isolation_eligible=True,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "A 513-bit RSA key is far below the 2048-bit minimum SP 800-131A Rev. 2 "
            "requires, and is factorable with modest classical effort."
        ),
    ),
    LabelledObservation(
        scenario_id="telnet_negotiation_a",
        src_ip="192.168.40.56",
        group=GROUP_HIGH,
        description="Telnet option-negotiation burst (existing deterministic fixture, reused).",
        expected_protocol=ProtocolType.TELNET,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=2,
        qrs_expected_total=7,
        qrs_expected_category=RiskCategory.HIGH,
        qrs_expected_isolation_eligible=True,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "Telnet is a cleartext interactive remote shell; credentials and session "
            "content are transmitted unprotected."
        ),
    ),
    LabelledObservation(
        scenario_id="telnet_negotiation_b",
        src_ip="192.168.40.57",
        group=GROUP_HIGH,
        description="Telnet option negotiation, different option set.",
        expected_protocol=ProtocolType.TELNET,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=2,
        qrs_expected_total=7,
        qrs_expected_category=RiskCategory.HIGH,
        qrs_expected_isolation_eligible=True,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "Telnet is a cleartext interactive remote shell; credentials and session "
            "content are transmitted unprotected."
        ),
    ),
    LabelledObservation(
        scenario_id="telnet_negotiation_c",
        src_ip="192.168.40.58",
        group=GROUP_HIGH,
        description="Telnet option negotiation including an AUTHENTICATION refusal.",
        expected_protocol=ProtocolType.TELNET,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=2,
        qrs_expected_port_risk=2,
        qrs_expected_total=7,
        qrs_expected_category=RiskCategory.HIGH,
        qrs_expected_isolation_eligible=True,
        external_security_label=LABEL_RISKY,
        security_rationale=(
            "Telnet is a cleartext interactive remote shell; this exchange also "
            "declines the AUTHENTICATION option."
        ),
    ),
    # --- INDETERMINATE (externally EXCLUDED) -----------------------------
    LabelledObservation(
        scenario_id="tls_encrypted_application_data",
        src_ip="192.168.40.61",
        group=GROUP_INDETERMINATE,
        description="TLS Application Data record (content type 0x17) carrying ciphertext.",
        expected_protocol=ProtocolType.HTTPS,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=0,
        qrs_expected_port_risk=0,
        qrs_expected_total=3,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_EXCLUDED,
        security_rationale=(
            "An encrypted record carries no version, cipher-suite or key evidence, so "
            "no standards-based judgment about the endpoint's configuration is possible "
            "from this packet. Retained for QRS conformance only."
        ),
    ),
    LabelledObservation(
        scenario_id="opaque_unclassified_payload",
        src_ip="192.168.40.62",
        group=GROUP_INDETERMINATE,
        description="Opaque payload matching no protocol signature; classified OTHER.",
        expected_protocol=ProtocolType.OTHER,
        qrs_expected_tls_risk=2,
        qrs_expected_key_size_risk=0,
        qrs_expected_pfs_risk=1,
        qrs_expected_entropy_risk=1,
        qrs_expected_port_risk=0,
        qrs_expected_total=4,
        qrs_expected_category=RiskCategory.MEDIUM,
        qrs_expected_isolation_eligible=False,
        external_security_label=LABEL_EXCLUDED,
        security_rationale=(
            "Traffic a payload-only fingerprinter cannot attribute to any known "
            "protocol; no standards-based safe/risky judgment is possible. Retained "
            "for QRS conformance only."
        ),
    ),
]

LABELLED_OBSERVATION_COUNT = len(LABELLED_OBSERVATIONS)

# The expected dataset size, declared independently of the packet
# generator so a silently dropped observation on either side fails a test
# rather than quietly shrinking the reported N.
EXPECTED_OBSERVATION_COUNT = 30

BINARY_OBSERVATIONS = [
    observation
    for observation in LABELLED_OBSERVATIONS
    if observation.participates_in_binary_metrics
]

RISK_CATEGORY_LABELS = [
    RiskCategory.LOW.value,
    RiskCategory.MEDIUM.value,
    RiskCategory.HIGH.value,
]


def observation_by_scenario_id(scenario_id: str) -> LabelledObservation:
    """Look one observation up by id.

    Raises:
        KeyError: if no observation carries that id.
    """
    for observation in LABELLED_OBSERVATIONS:
        if observation.scenario_id == scenario_id:
            return observation
    raise KeyError(f"no labelled observation with scenario_id {scenario_id!r}")


def label_counts() -> dict:
    """Count observations per external security label."""
    return {
        label: sum(
            1
            for observation in LABELLED_OBSERVATIONS
            if observation.external_security_label == label
        )
        for label in EXTERNAL_LABELS
    }


def group_counts() -> dict:
    """Count observations per scenario group."""
    return {
        group: sum(
            1 for observation in LABELLED_OBSERVATIONS if observation.group == group
        )
        for group in GROUPS
    }


__all__ = [
    "LabelledObservation",
    "LABELLED_OBSERVATIONS",
    "LABELLED_OBSERVATION_COUNT",
    "EXPECTED_OBSERVATION_COUNT",
    "BINARY_OBSERVATIONS",
    "LABELLED_SET_PCAP_PATH",
    "LABELLED_SET_SIZE",
    "GROUPS",
    "GROUP_SECURE",
    "GROUP_MODERATE",
    "GROUP_HIGH",
    "GROUP_INDETERMINATE",
    "EXTERNAL_LABELS",
    "BINARY_LABELS",
    "LABEL_SAFE",
    "LABEL_RISKY",
    "LABEL_EXCLUDED",
    "EXTERNAL_RUBRIC_CITATIONS",
    "RISK_CATEGORY_LABELS",
    "observation_by_scenario_id",
    "label_counts",
    "group_counts",
]
