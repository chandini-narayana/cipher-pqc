"""IsolationBackend — the hardware-execution boundary for high-risk
device isolation, and its only Phase 1 implementation, NoOpIsolationBackend.

Phase 1 (this codebase's current state) is Windows and hardware-free.
The Execution Report also does not specify enough of an actual iptables
strategy (chain, INPUT vs. FORWARD, source vs. destination rule
direction, DROP vs. REJECT, duplicate-rule semantics, restoration
semantics, or privilege model) to implement one without inventing
firewall policy. Real enforcement — a Linux/Raspberry-Pi iptables
backend — is therefore deliberately deferred to hardware integration,
not built here.

`NoOpIsolationBackend` is the only concrete backend in this phase. It
never calls subprocess, never touches iptables or the Windows
Firewall, never requires administrator privileges, and never claims
that isolation was physically enforced — it only records that
isolation was *requested* and logs why enforcement did not happen.
This keeps "isolation decided" and "isolation enforced" as two
distinct, honestly-reported facts, never conflated.

A future Raspberry Pi backend is swapped in at the composition root
(main.py / run_api.py), exactly like `capture.factory.get_capture_source`
already swaps `OfflinePcapSource`/`LiveCaptureSource` — never via
platform-sniffing inside this module or inside pipeline/runner.py.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class IsolationOutcome:
    """The result of one isolation attempt — small, ephemeral, and
    purely for logging/audit. Never persisted to a database; never a
    models/ domain object (isolation is a runtime enforcement concern,
    not a fused assessment fact).

    `requested` is always True when a backend's isolate() returns
    normally (an attempt was genuinely made); `enforced` distinguishes
    whether that attempt actually changed anything on the network.
    """

    device_ip: str
    risk_score: int
    requested_at: datetime
    requested: bool
    enforced: bool
    reason: str


class IsolationBackend(ABC):
    """Abstract hardware-execution boundary for isolating a device.

    No `restore()` in this phase: nothing here calls it, and restoration
    semantics are exactly the kind of undefined-by-the-Execution-Report
    firewall policy (see module docstring) this phase must not invent.
    """

    @abstractmethod
    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        """Attempt to isolate `device_ip`, whose raw QRS was
        `risk_score`. Must not raise for an ordinary "unsupported on
        this platform" outcome — return an IsolationOutcome with
        `enforced=False` and an explanatory `reason` instead."""
        raise NotImplementedError  # pragma: no cover - interface only


class NoOpIsolationBackend(IsolationBackend):
    """The only concrete isolation backend implemented in Phase 1.

    Never calls subprocess, iptables, or the Windows Firewall API;
    never requires administrator privileges; never reports a
    successful physical isolation. Logs one clear WARNING per attempt
    so the decision is visible in normal application logs even though
    no network action was taken.
    """

    _REASON = "Hardware enforcement unavailable in current deployment"

    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        logger.warning(
            "Isolation requested for device %s (QRS=%d) but hardware enforcement "
            "is unavailable in the current deployment (Windows, hardware-free "
            "Phase 1) — decision recorded, no network action taken.",
            device_ip,
            risk_score,
        )
        return IsolationOutcome(
            device_ip=device_ip,
            risk_score=risk_score,
            requested_at=datetime.now(timezone.utc),
            requested=True,
            enforced=False,
            reason=self._REASON,
        )
