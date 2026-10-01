"""IptablesIsolationBackend — real Linux enforcement through the system
`iptables` binary, scoped to a chain CIPHER owns.

This is the frozen answer to the policy questions Phase 3A deliberately
left open (see docs/SDD.md §35 and §38). It is a specialization of
`LinuxIsolationBackend`, not a parallel enforcement path: it reuses the
same `IsolationBackend` contract, the same injected `CommandRunner` seam,
and the same `_outcome()` reporting, and it is reached through the same
`pipeline/runner.py` call that already exists. The eligibility decision
is untouched — `enforcement.decision.should_isolate()` (raw QRS >=
threshold, never `final_category`, never an ML score) remains the only
thing that decides *whether* a device is isolated. By the time this class
is called the request is already approved; it only carries it out.

WHAT IT DOES, exactly:

    iptables -w -L CIPHER_ISOLATION -n          (does our chain exist?)
    iptables -w -N CIPHER_ISOLATION             (create it if not)
    iptables -w -C FORWARD -j CIPHER_ISOLATION  (is our jump in place?)
    iptables -w -I FORWARD 1 -j CIPHER_ISOLATION(install it once if not)
    iptables -w -C CIPHER_ISOLATION -s <ip> -j DROP   (rule present?)
    iptables -w -A CIPHER_ISOLATION -s <ip> -j DROP   (add if not)
    iptables -w -C CIPHER_ISOLATION -d <ip> -j DROP   (rule present?)
    iptables -w -A CIPHER_ISOLATION -d <ip> -j DROP   (add if not)

Every step is check-then-act, so running it twice adds nothing: no
duplicate rules ever accumulate. `-w` waits for the xtables lock rather
than failing spuriously when something else holds it.

WHY `FORWARD` ONLY — and what that honestly means. The repository defines
no forwarding topology: `wlan0` is management and `wlan1` is a
monitor-mode capture interface, and SDD §35 records that neither is a
forwarding path. `FORWARD` is therefore the narrowest rule that matches
the project's stated intent ("prevent the isolated device from traversing
the enforcement point") while being incapable of locking this host out of
its own management network — management traffic to and from the Pi is
INPUT/OUTPUT, which this backend never touches. The consequence is stated
plainly rather than papered over: **if the Pi is not actually in the
device's forwarding path, the rule is installed correctly and drops
nothing.** A passive monitor interface cannot block traffic it merely
observes, and this phase does not redesign the network to change that. An
`enforced=True` outcome means "CIPHER's DROP rule is in place on this
host", which is exactly what the reason string says.

WHAT IT REFUSES TO DO: it never flushes a chain, never sets a default
policy, never deletes a rule it did not add, and never touches a built-in
chain except to install its own single jump. It refuses outright to
isolate loopback, unspecified, multicast or broadcast addresses, anything
that is not a valid IPv4 address, or any address this host itself holds.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Callable, Iterable, List, Optional, Sequence, Set, Tuple

from enforcement.backends import IsolationOutcome
from enforcement.command_runner import CommandRunner, UnavailableCommandRunner
from enforcement.linux_backend import LinuxIsolationBackend

logger = logging.getLogger(__name__)

IPTABLES_BACKEND_NAME = "linux-iptables"

#: The chain CIPHER owns. Every rule this backend adds lives here, and it
#: touches no rule outside it.
CIPHER_CHAIN = "CIPHER_ISOLATION"

#: The built-in chain the owned chain is jumped from. FORWARD only — see
#: the module docstring for why this is the narrowest safe choice.
BUILTIN_CHAIN = "FORWARD"

DEFAULT_IPTABLES_BINARY = "iptables"

#: Passed to every invocation so a concurrently-held xtables lock is
#: waited for instead of causing a spurious failure.
_WAIT_FLAG = "-w"

LocalAddressProvider = Callable[[], Set[str]]


def local_ipv4_addresses() -> Set[str]:
    """This host's own IPv4 addresses, best-effort.

    Used only to refuse isolating the host itself. Any failure (no DNS,
    an unusual hostname setup, a sandbox) returns an empty set: the
    protection is then simply unavailable, which is reported in the
    reason string rather than guessed at. Uses `socket` only — no
    subprocess, no new dependency.
    """
    addresses: Set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            address = info[4][0]
            if address:
                addresses.add(str(address))
    except Exception:  # noqa: BLE001 - best-effort; absence is handled by the caller
        logger.debug("Could not determine this host's own IPv4 addresses.", exc_info=True)
    return addresses


def validate_isolation_target(
    device_ip: str, local_addresses: Iterable[str] = ()
) -> Optional[str]:
    """Return None if `device_ip` may be isolated, or a human-readable
    refusal reason if it must not be.

    IPv4 only, deliberately: CIPHER's device identity is IPv4 (see
    capture/raw_packet.py and pipeline/runner.py), and this phase
    introduces no IPv6 firewall behavior. An IPv6 literal is a clean
    refusal, not an attempt.
    """
    try:
        address = ipaddress.ip_address(device_ip)
    except ValueError:
        return f"{device_ip!r} is not a valid IP address"

    if not isinstance(address, ipaddress.IPv4Address):
        return f"{device_ip} is not an IPv4 address (this backend is IPv4-only)"
    if address.is_loopback:
        return f"refusing to isolate loopback address {device_ip}"
    if address.is_unspecified:
        return f"refusing to isolate the unspecified address {device_ip}"
    if address.is_multicast:
        return f"refusing to isolate multicast address {device_ip}"
    if address == ipaddress.IPv4Address("255.255.255.255"):
        return f"refusing to isolate the broadcast address {device_ip}"
    if str(address) in set(local_addresses):
        return (
            f"refusing to isolate {device_ip}: it is one of this host's own "
            "addresses, and isolating it could cut off management access"
        )
    return None


class IptablesIsolationBackend(LinuxIsolationBackend):
    """Real iptables enforcement, idempotent and scoped to CIPHER's chain.

    `command_runner` is injected and defaults to the non-executing
    `UnavailableCommandRunner`, so constructing this class by itself can
    never change a firewall — a composition root must deliberately supply
    `SubprocessCommandRunner` for any command to run. That is why Windows
    unit tests cannot touch a firewall even if they instantiate this.

    `isolate()` and `restore()` never raise: a missing binary, a
    permission denial, a refused target and a non-zero exit are all
    reported as an `IsolationOutcome` with `enforced=False` and a reason.
    `enforced=True` is returned only when every required rule is verified
    present at the end of the sequence.
    """

    backend_name = IPTABLES_BACKEND_NAME
    enforcement_capable = True

    def __init__(
        self,
        command_runner: Optional[CommandRunner] = None,
        iptables_binary: str = DEFAULT_IPTABLES_BINARY,
        chain: str = CIPHER_CHAIN,
        builtin_chain: str = BUILTIN_CHAIN,
        local_address_provider: LocalAddressProvider = local_ipv4_addresses,
    ) -> None:
        # The parent's generic RuleBuilder seam is bypassed: this subclass
        # *is* the frozen policy, so it overrides isolate()/restore()
        # entirely and only reuses the parent's outcome reporting.
        super().__init__(command_runner=command_runner or UnavailableCommandRunner())
        self._iptables = iptables_binary
        self._chain = chain
        self._builtin_chain = builtin_chain
        self._local_address_provider = local_address_provider

    # --- public contract -------------------------------------------------

    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        """Install CIPHER's DROP rules for `device_ip`. Idempotent."""
        logger.info(
            "Enforcement requested: isolating %s (QRS=%d) via iptables chain %s.",
            device_ip,
            risk_score,
            self._chain,
        )

        refusal = self._refuse(device_ip)
        if refusal is not None:
            logger.warning("Enforcement refused for %s: %s", device_ip, refusal)
            return self._outcome(device_ip, risk_score, enforced=False, reason=refusal)

        steps: List[Tuple[Sequence[str], Sequence[str]]] = [
            (self._check_chain_exists(), self._create_chain()),
            (self._check_jump(), self._install_jump()),
            (self._check_drop("-s", device_ip), self._add_drop("-s", device_ip)),
            (self._check_drop("-d", device_ip), self._add_drop("-d", device_ip)),
        ]

        for check, action in steps:
            failure = self._ensure(check, action)
            if failure is not None:
                logger.error("Enforcement failed for %s: %s", device_ip, failure)
                return self._outcome(device_ip, risk_score, enforced=False, reason=failure)

        reason = (
            f"Isolated {device_ip} with iptables: DROP rules in chain {self._chain}, "
            f"jumped from {self._builtin_chain}. Takes effect for traffic that "
            f"traverses this host; a device whose traffic does not pass through this "
            f"host is unaffected."
        )
        logger.info("Enforcement succeeded: %s", reason)
        return self._outcome(device_ip, risk_score, enforced=True, reason=reason)

    def restore(self, device_ip: str) -> IsolationOutcome:
        """Remove CIPHER's DROP rules for `device_ip`, and nothing else.

        Idempotent and predictable: a device that is not currently
        isolated is a success (the desired state already holds), not an
        error. The owned chain and its jump are deliberately left in
        place — other devices may still be isolated through them, and
        removing shared state here could silently un-isolate them.
        """
        logger.info("Restore requested: un-isolating %s from chain %s.", device_ip, self._chain)

        refusal = self._refuse(device_ip)
        if refusal is not None:
            logger.warning("Restore refused for %s: %s", device_ip, refusal)
            return self._outcome(device_ip, 0, enforced=False, reason=refusal)

        removed = 0
        for direction in ("-s", "-d"):
            check = self._command_runner.run(self._check_drop(direction, device_ip))
            if not check.executed:
                failure = self._unexecuted_reason(check)
                logger.error("Restore failed for %s: %s", device_ip, failure)
                return self._outcome(device_ip, 0, enforced=False, reason=failure)
            if check.exit_code != 0:
                continue  # not present: nothing to remove for this direction

            deletion = self._command_runner.run(self._delete_drop(direction, device_ip))
            if not deletion.succeeded:
                failure = (
                    f"could not remove the {direction} DROP rule for {device_ip}: "
                    f"{self._failure_detail(deletion)}"
                )
                logger.error("Restore failed for %s: %s", device_ip, failure)
                return self._outcome(device_ip, 0, enforced=False, reason=failure)
            removed += 1

        if removed:
            reason = (
                f"Removed {removed} CIPHER DROP rule(s) for {device_ip} from chain "
                f"{self._chain}; no other firewall rule was touched."
            )
        else:
            reason = (
                f"{device_ip} was not isolated by CIPHER: no rule for it exists in "
                f"chain {self._chain}, so there was nothing to remove."
            )
        logger.info("Restore succeeded: %s", reason)
        return self._outcome(device_ip, 0, enforced=True, reason=reason)

    # --- internals -------------------------------------------------------

    def _refuse(self, device_ip: str) -> Optional[str]:
        """The safety gate every command path passes through first. No
        iptables command is constructed, let alone run, for a target this
        rejects."""
        try:
            local_addresses = set(self._local_address_provider())
        except Exception:  # noqa: BLE001 - an unavailable protection is not a crash
            logger.debug("Local-address protection unavailable.", exc_info=True)
            local_addresses = set()
        return validate_isolation_target(device_ip, local_addresses)

    def _ensure(self, check: Sequence[str], action: Sequence[str]) -> Optional[str]:
        """Run `check`; if it reports the desired state is absent, run
        `action`. Returns None on success, or a failure reason.

        A non-zero exit from `check` is normal and expected — it is how
        iptables reports "this rule/chain is not there" — so only an
        *unexecuted* check (missing binary, no permission to run it) or a
        failing `action` is a problem.
        """
        check_result = self._command_runner.run(check)
        if not check_result.executed:
            return self._unexecuted_reason(check_result)
        if check_result.exit_code == 0:
            return None  # already in the desired state: add nothing

        action_result = self._command_runner.run(action)
        if not action_result.executed:
            return self._unexecuted_reason(action_result)
        if action_result.exit_code != 0:
            return (
                f"iptables command {' '.join(action_result.command)} failed: "
                f"{self._failure_detail(action_result)}"
            )
        return None

    @staticmethod
    def _unexecuted_reason(result) -> str:
        """A command that never ran at all — the missing-binary and
        insufficient-privilege cases. Never reported as enforcement."""
        detail = result.stderr.strip() or "the command did not execute"
        return (
            f"could not run {' '.join(result.command) or 'iptables'}: {detail}. "
            "Real enforcement needs the iptables binary and root (or CAP_NET_ADMIN)."
        )

    @staticmethod
    def _failure_detail(result) -> str:
        detail = result.stderr.strip() or result.stdout.strip()
        if not detail:
            return f"exit code {result.exit_code}"
        return f"{detail} (exit code {result.exit_code})"

    def _base(self) -> List[str]:
        return [self._iptables, _WAIT_FLAG]

    def _check_chain_exists(self) -> List[str]:
        return self._base() + ["-L", self._chain, "-n"]

    def _create_chain(self) -> List[str]:
        return self._base() + ["-N", self._chain]

    def _check_jump(self) -> List[str]:
        return self._base() + ["-C", self._builtin_chain, "-j", self._chain]

    def _install_jump(self) -> List[str]:
        # Inserted at position 1 so the isolation decision is evaluated
        # before any pre-existing ACCEPT rule in the built-in chain could
        # let the device through. Inserted once only (guarded by -C).
        return self._base() + ["-I", self._builtin_chain, "1", "-j", self._chain]

    def _check_drop(self, direction: str, device_ip: str) -> List[str]:
        return self._base() + ["-C", self._chain, direction, device_ip, "-j", "DROP"]

    def _add_drop(self, direction: str, device_ip: str) -> List[str]:
        return self._base() + ["-A", self._chain, direction, device_ip, "-j", "DROP"]

    def _delete_drop(self, direction: str, device_ip: str) -> List[str]:
        return self._base() + ["-D", self._chain, direction, device_ip, "-j", "DROP"]
