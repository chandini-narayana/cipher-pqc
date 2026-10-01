"""LinuxIsolationBackend — the location a real Raspberry-Pi/Linux
enforcement backend will live, wired end-to-end against injected,
mockable seams, but with the firewall policy itself still unfrozen.

Why this module exists now, before any rule is written: the backend
*contract* (what the pipeline calls, what it gets back, how a failure is
surfaced) must be settled before the Pi is in the loop, so that adding
real enforcement later is a one-file change that cannot reach back into
`should_isolate()`, `pipeline/runner.py`, or any composition root. What
is deliberately NOT decided here — and must not be guessed — is the
network policy:

  * which interface the rule applies to (wlan0 is management, wlan1 is
    the monitor-mode AR9271; neither is a forwarding path yet),
  * IP-based vs. MAC-based enforcement,
  * FORWARD vs. INPUT/OUTPUT chain,
  * nftables vs. iptables,
  * the gateway/NAT topology the Pi would have to own to enforce at all,
  * DROP vs. REJECT, duplicate-rule semantics, restoration semantics,
    and the privilege model.

Those are decided on the Pi once the controlled enforcement topology is
frozen, and they arrive here as a `RuleBuilder` plus an executing
`CommandRunner` — not as edits to CIPHER's pipeline.

Lives in its own module, not in backends.py, for two reasons: backends.py
is statically asserted to contain `NoOpIsolationBackend` as its only
concrete backend and to import neither `subprocess` nor `os`, and a
Windows deployment never needs to import this module at all.

This module also imports neither `subprocess` nor `os`. All execution
goes through `enforcement.command_runner.CommandRunner`, whose only
implementation in this phase, `UnavailableCommandRunner`, never spawns a
process.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable, Optional, Sequence

from enforcement.backends import IsolationBackend, IsolationOutcome
from enforcement.command_runner import CommandRunner, UnavailableCommandRunner
from utils.exceptions import CipherError

logger = logging.getLogger(__name__)

LINUX_BACKEND_NAME = "linux"

#: A RuleBuilder turns a device identifier into the ordered argv sequences
#: that would isolate (or restore) it. One list per command, so a policy
#: needing two rules is expressible without changing this interface.
RuleBuilder = Callable[[str], Sequence[Sequence[str]]]


class IsolationPolicyNotFrozenError(CipherError):
    """Raised by `unfrozen_rule_builder` to make the absence of a frozen
    firewall policy an explicit, named condition rather than a silently
    empty command list.

    Never escapes `LinuxIsolationBackend.isolate()`: it is caught there
    and reported as a non-enforced `IsolationOutcome`, exactly like any
    other enforcement failure."""


def unfrozen_rule_builder(device_identifier: str) -> Sequence[Sequence[str]]:
    """The default RuleBuilder: refuses to invent a firewall rule.

    Replaced — not edited — once the controlled enforcement topology is
    frozen on the Pi (see module docstring for the exact list of
    decisions that replacement encodes).
    """
    raise IsolationPolicyNotFrozenError(
        "No Linux isolation rule is defined for device "
        f"{device_identifier}: the controlled enforcement topology "
        "(interface, IP vs. MAC, chain, iptables vs. nftables, "
        "gateway/NAT path) is not frozen yet, so no firewall command "
        "may be constructed."
    )


class LinuxIsolationBackend(IsolationBackend):
    """Linux enforcement backend with both of its policy-bearing parts
    injected: a `RuleBuilder` (what to run) and a `CommandRunner` (how to
    run it).

    Both default to the deliberately non-functional implementations, so
    constructing this backend with no arguments — on any platform,
    including accidentally on Windows — cannot produce a firewall
    change: it reports `requested=True, enforced=False` with a reason
    naming the unfrozen policy.

    `isolate()` never raises. A failing rule builder, a runner that
    never executed, and a command that executed with a non-zero exit
    code are all reported the same honest way: `enforced=False` plus a
    `reason`. Enforcement is only ever claimed when every constructed
    command actually executed and succeeded.
    """

    backend_name = LINUX_BACKEND_NAME

    def __init__(
        self,
        command_runner: Optional[CommandRunner] = None,
        rule_builder: RuleBuilder = unfrozen_rule_builder,
        restore_rule_builder: Optional[RuleBuilder] = None,
    ) -> None:
        self._command_runner: CommandRunner = command_runner or UnavailableCommandRunner()
        self._rule_builder = rule_builder
        self._restore_rule_builder = restore_rule_builder

    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        """Attempt to isolate `device_ip`. See class docstring: never
        raises, never claims unverified enforcement."""
        return self._apply(device_ip, risk_score, self._rule_builder, "isolate")

    def restore(self, device_ip: str) -> IsolationOutcome:
        """Attempt to reverse a previous isolation of `device_ip`.

        Restoration policy is as unfrozen as isolation policy, so with no
        `restore_rule_builder` injected this reports the interface
        default (`enforced=False`) rather than guessing at a rule to
        delete."""
        if self._restore_rule_builder is None:
            return super().restore(device_ip)
        return self._apply(device_ip, 0, self._restore_rule_builder, "restore")

    def _apply(
        self,
        device_identifier: str,
        risk_score: int,
        rule_builder: RuleBuilder,
        action: str,
    ) -> IsolationOutcome:
        try:
            commands = rule_builder(device_identifier)
        except Exception as exc:  # noqa: BLE001 - a policy gap is an outcome, not a crash
            return self._outcome(
                device_identifier,
                risk_score,
                enforced=False,
                reason=f"{action} rule construction failed: {exc}",
            )

        if not commands:
            return self._outcome(
                device_identifier,
                risk_score,
                enforced=False,
                reason=f"{action} rule builder produced no command",
            )

        for command in commands:
            try:
                result = self._command_runner.run(command)
            except Exception as exc:  # noqa: BLE001 - a runner failure is an outcome too
                return self._outcome(
                    device_identifier,
                    risk_score,
                    enforced=False,
                    reason=f"{action} command runner raised: {exc}",
                )

            if not result.succeeded:
                detail = result.stderr.strip() or f"exit code {result.exit_code}"
                return self._outcome(
                    device_identifier,
                    risk_score,
                    enforced=False,
                    reason=(
                        f"{action} command {' '.join(result.command)} did not succeed: {detail}"
                    ),
                )

        logger.info(
            "Linux backend completed %s for device %s (%d command(s)).",
            action,
            device_identifier,
            len(commands),
        )
        return self._outcome(
            device_identifier,
            risk_score,
            enforced=True,
            reason=f"{action} enforced via injected command runner",
        )

    def _outcome(
        self, device_identifier: str, risk_score: int, *, enforced: bool, reason: str
    ) -> IsolationOutcome:
        if not enforced:
            logger.warning(
                "Linux isolation backend did not enforce for device %s: %s",
                device_identifier,
                reason,
            )
        return IsolationOutcome(
            device_ip=device_identifier,
            risk_score=risk_score,
            requested_at=datetime.now(timezone.utc),
            requested=True,
            enforced=enforced,
            reason=reason,
            backend=self.backend_name,
        )
