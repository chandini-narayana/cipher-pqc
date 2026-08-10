"""CipherError hierarchy (see docs/SDD.md Section 12).

Only the members Step 5 (capture/) actually needs are implemented here:
CipherError, CaptureError, LiveCaptureNotImplementedError, and
ParsingError. The remaining planned members — RiskEngineError,
ModelNotFoundError, SigningError, ReportGenerationError — are added in
their respective future steps, not speculatively here.
"""
from __future__ import annotations


class CipherError(Exception):
    """Base class for all CIPHER-specific exceptions."""


class CaptureError(CipherError):
    """Raised for capture-layer failures: a missing/corrupt .pcap file,
    an unrecognized capture_mode, or (once implemented) a NIC that
    can't be opened."""


class LiveCaptureNotImplementedError(CaptureError):
    """Raised by LiveCaptureSource.read_packets() (see docs/SDD.md D2).

    A deliberate, immediate failure, not a bug: live capture is a
    documented Phase 1 scaffold, not yet implemented. Raised the moment
    read_packets() is called, before any iteration is attempted, so
    CAPTURE_MODE=live fails loudly at startup rather than producing a
    quietly-empty dashboard later.
    """


class ParsingError(CipherError):
    """Raised when a single packet cannot be parsed into a RawPacket —
    e.g., an IP/transport layer scapy exposes in a shape RawPacket's
    own validation rejects. Reserved for per-packet failures; a
    corrupt or unreadable .pcap file itself raises CaptureError."""