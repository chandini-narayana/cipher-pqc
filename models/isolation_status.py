"""IsolationStatus — the API/report-facing record of one isolation
attempt for a device.

This is the `models/` projection of `enforcement.backends.IsolationOutcome`,
not a second copy of it. The two exist separately on purpose:

  * `IsolationOutcome` is the runtime enforcement result — ephemeral,
    produced by a hardware backend, and living in `enforcement/` where
    the backend contract lives.
  * `IsolationStatus` is the *reportable fact* that an attempt happened
    and how it went. It is attached to `DeviceAssessment`, so it is
    serialized over REST, rendered into the PDF, and covered by the
    Dilithium signature — which means it must be a plain `models/` type
    with the same `to_dict`/`from_dict` conventions as its siblings, and
    `models/` must not import `enforcement` to obtain it.

`enforcement.backends.IsolationOutcome.to_status()` performs the
conversion (enforcement already depends on models; the reverse direction
is never introduced).

Deliberately does **not** repeat `device_ip` or `risk_score`: both
already exist on the surrounding `DeviceAssessment`
(`device.ip`, `risk_assessment.risk_score`), and duplicating them would
create two places where they could disagree.

`enforcement_capable` is what keeps the display honest. Without it,
`enforced=False` is ambiguous — it could mean "this deployment does not
enforce at all" (Windows/NoOp) or "a real backend tried and failed". The
flag is set by the backend itself, defaults to `False` (never claim a
capability that was not asserted), and is the only thing separating
`"Requested / not enforced"` from `"Failed"` in `status_label`.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

#: `status_label` values — the four compact display states. Exposed as
#: constants so a display layer can match on them without re-deriving
#: the logic (and without importing `enforcement`).
NOT_REQUESTED = "Not requested"
REQUESTED_NOT_ENFORCED = "Requested / not enforced"
ENFORCED = "Enforced"
FAILED = "Failed"


@dataclass(frozen=True, slots=True)
class IsolationStatus:
    """The outcome of one isolation attempt, as exposed to the API,
    dashboard and signed report.

    No validation beyond what the backend already established: this type
    records what happened, it never decides anything. In particular it
    carries no threshold and no eligibility logic — eligibility is
    `enforcement.decision.should_isolate()`'s job, and the mere
    *existence* of an IsolationStatus is the record that the device was
    found eligible.
    """

    requested: bool
    enforced: bool
    backend: str
    reason: str
    requested_at: datetime
    enforcement_capable: bool = False

    @property
    def status_label(self) -> str:
        """One of ENFORCED / FAILED / REQUESTED_NOT_ENFORCED — the
        compact state a display layer shows.

        NOT_REQUESTED is deliberately not produced here: an
        IsolationStatus only exists when an attempt was made, so "not
        requested" is the *absence* of this object
        (`DeviceAssessment.isolation is None`).
        """
        if self.enforced:
            return ENFORCED
        if self.enforcement_capable:
            return FAILED
        return REQUESTED_NOT_ENFORCED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested": self.requested,
            "enforced": self.enforced,
            "backend": self.backend,
            "reason": self.reason,
            "requested_at": self.requested_at.isoformat(),
            "enforcement_capable": self.enforcement_capable,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IsolationStatus":
        return cls(
            requested=data["requested"],
            enforced=data["enforced"],
            backend=data["backend"],
            reason=data["reason"],
            requested_at=datetime.fromisoformat(data["requested_at"]),
            # Tolerated as absent so a payload serialized before this
            # field existed still loads — and defaults to the safe
            # reading, never claiming an enforcement capability.
            enforcement_capable=data.get("enforcement_capable", False),
        )
