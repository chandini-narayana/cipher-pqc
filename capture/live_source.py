"""LiveCaptureSource — DOCUMENTED SCAFFOLD ONLY in Phase 1 (SDD D2).

This class will implement CaptureSource against a real network
interface via scapy.sniff() in a later step. In Phase 1 it exists so
the interface, the factory wiring, and CAPTURE_MODE=live all have a
real, loudly-failing target rather than a silent gap.

read_packets() is a plain (non-generator) method that raises
LiveCaptureNotImplementedError immediately when called — not lazily on
first iteration — so a misconfigured CAPTURE_MODE=live fails the
moment something tries to use it, not as a quietly-empty dashboard
discovered later.
"""
from __future__ import annotations

from typing import Iterator, Optional

from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from utils.exceptions import LiveCaptureNotImplementedError


class LiveCaptureSource(CaptureSource):
    """Real-NIC capture — not implemented in Phase 1.

    Raises:
        LiveCaptureNotImplementedError: always, immediately, from
            read_packets().
    """

    def __init__(self, interface: Optional[str]) -> None:
        self._interface = interface

    def read_packets(self) -> Iterator[RawPacket]:
        raise LiveCaptureNotImplementedError(
            "Live capture is not implemented in Phase 1. Use "
            "CAPTURE_MODE=offline or CAPTURE_MODE=mock instead. See "
            "docs/SDD.md Section 4 (D2) for the plan to implement this."
        )