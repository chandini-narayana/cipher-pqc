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

The Linux backend now has a home — `enforcement.linux_backend.
LinuxIsolationBackend` — but still constructs no firewall command: its
rule builder and command runner are injected, and both defaults refuse
to act. It lives in that separate module, not here, so that this module
provably stays the NoOp-only, subprocess-free one.

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

from models.isolation_status import IsolationStatus

logger = logging.getLogger(__name__)

_UNKNOWN_BACKEND = "unknown"
NOOP_BACKEND_NAME = "noop"

_RESTORE_UNSUPPORTED_REASON = "Restoration is not supported by this backend"


@dataclass(frozen=True, slots=True)
class IsolationOutcome:
    """The result of one isolation attempt — small, ephemeral, and
    purely for logging/audit. Never persisted to a database; never a
    models/ domain object (isolation is a runtime enforcement concern,
    not a fused assessment fact).

    `requested` is always True when a backend's isolate() returns
    normally (an attempt was genuinely made); `enforced` distinguishes
    whether that attempt actually changed anything on the network.
    `backend` names which concrete backend produced this outcome (e.g.
    "noop", "linux"), so an audit log can tell a deliberately
    non-enforcing deployment apart from a real one that failed; it
    defaults to "unknown" only so that existing positional
    constructions keep working unchanged.
    """

    device_ip: str
    risk_score: int
    requested_at: datetime
    requested: bool
    enforced: bool
    reason: str
    backend: str = _UNKNOWN_BACKEND
    enforcement_capable: bool = False

    def to_status(self) -> IsolationStatus:
        """Project this runtime outcome into the models/ type that
        DeviceAssessment, the REST API, and the signed report consume.

        `device_ip`/`risk_score` are deliberately dropped: the
        surrounding DeviceAssessment already carries both, and two copies
        could disagree. This is the only direction of travel — models/
        never imports enforcement/.
        """
        return IsolationStatus(
            requested=self.requested,
            enforced=self.enforced,
            backend=self.backend,
            reason=self.reason,
            requested_at=self.requested_at,
            enforcement_capable=self.enforcement_capable,
        )


class IsolationBackend(ABC):
    """Abstract hardware-execution boundary for isolating a device.

    `isolate()` is the only abstract method, so every existing backend
    (and every test double) remains instantiable unchanged. `restore()`
    is a concrete, deliberately non-enforcing default: the restoration
    *policy* (which rule to remove, in which chain, whether a device
    may ever be un-isolated automatically at all) is exactly the kind
    of undefined-by-the-Execution-Report firewall policy this phase
    must not invent — but the *seam* for it belongs on the interface so
    a future Linux backend can override it without the pipeline or any
    caller changing shape. Nothing in CIPHER calls `restore()` today.
    """

    #: Name recorded in IsolationOutcome.backend. Overridden per backend.
    backend_name: str = _UNKNOWN_BACKEND

    #: Whether this backend performs real network enforcement at all.
    #: False for every deliberately non-enforcing backend. Default False:
    #: a backend must opt in to claiming the capability.
    enforcement_capable: bool = False

    @abstractmethod
    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        """Attempt to isolate `device_ip`, whose raw QRS was
        `risk_score`. Must not raise for an ordinary "unsupported on
        this platform" outcome — return an IsolationOutcome with
        `enforced=False` and an explanatory `reason` instead."""
        raise NotImplementedError  # pragma: no cover - interface only

    def restore(self, device_ip: str) -> IsolationOutcome:
        """Attempt to reverse a previous isolation of `device_ip`.

        The default implementation enforces nothing and reports exactly
        that — `requested=True`, `enforced=False`, with a `reason`
        naming restoration as unsupported. Like `isolate()`, it must
        never raise for an ordinary unsupported/failed outcome.
        """
        logger.warning(
            "Restore requested for device %s but backend %s does not implement "
            "restoration — no network action taken.",
            device_ip,
            self.backend_name,
        )
        return IsolationOutcome(
            device_ip=device_ip,
            risk_score=0,
            requested_at=datetime.now(timezone.utc),
            requested=True,
            enforced=False,
            reason=_RESTORE_UNSUPPORTED_REASON,
            backend=self.backend_name,
            enforcement_capable=self.enforcement_capable,
        )


class NoOpIsolationBackend(IsolationBackend):
    """The only concrete isolation backend implemented in Phase 1.

    Never calls subprocess, iptables, or the Windows Firewall API;
    never requires administrator privileges; never reports a
    successful physical isolation. Logs one clear WARNING per attempt
    so the decision is visible in normal application logs even though
    no network action was taken.
    """

    _REASON = "Hardware enforcement unavailable in current deployment"

    backend_name = NOOP_BACKEND_NAME
    enforcement_capable = False

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
            backend=self.backend_name,
            enforcement_capable=self.enforcement_capable,
        )
