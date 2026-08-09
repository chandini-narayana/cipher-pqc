"""ProtocolFingerprint — TLS/RSA and protocol-exposure facts about a packet.

Populated by fingerprint/ (not implemented in this step). Holds only
the extracted facts — no extraction logic, no scoring.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from models._validation import validate_non_empty
from models.enums import ProtocolType, TLSVersion


@dataclass(frozen=True, slots=True)
class ProtocolFingerprint:
    """The protocol-level facts fingerprint/ extracts from a connection.

    Raises:
        ValueError: if `key_size` is present and not positive, or if
            `cipher_suite` is present but empty.
    """

    protocol: ProtocolType
    tls_version: Optional[TLSVersion]
    key_size: Optional[int]
    forward_secrecy: bool
    cipher_suite: Optional[str] = None

    def __post_init__(self) -> None:
        if self.key_size is not None and self.key_size <= 0:
            raise ValueError(f"key_size must be positive, got {self.key_size}")
        if self.cipher_suite is not None:
            validate_non_empty("cipher_suite", self.cipher_suite)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol.value,
            "tls_version": self.tls_version.value if self.tls_version else None,
            "key_size": self.key_size,
            "forward_secrecy": self.forward_secrecy,
            "cipher_suite": self.cipher_suite,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtocolFingerprint":
        tls_version = data.get("tls_version")
        return cls(
            protocol=ProtocolType(data["protocol"]),
            tls_version=TLSVersion(tls_version) if tls_version is not None else None,
            key_size=data.get("key_size"),
            forward_secrecy=data["forward_secrecy"],
            cipher_suite=data.get("cipher_suite"),
        )