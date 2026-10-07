"""Read-only facts about the appliance's own capture interface, and the
appliance-level guard that keeps the appliance from isolating itself.

Why this exists. `enforcement.iptables_backend.local_ipv4_addresses()` finds
this host's addresses by resolving its hostname, which on a stock Debian image
usually yields only `127.0.1.1` from /etc/hosts. On the AP topology the
appliance's own lab address (for example 192.168.50.1 on wlan1) is then
missing, so it is neither excluded from the protected scope nor refused as an
isolation target. The capture interface's own IPv4 address is the one address
the appliance is guaranteed to hold on the protected network, so it is read
directly from the interface and added to both sets.

Strictly read-only: one `SIOCGIFADDR` ioctl and one read of
`/sys/class/net/<iface>/ifindex`. Nothing here changes an interface, its mode,
its addresses, or any service — no `ip`, `iw`, `nmcli` or `hostapd` call, and
no repair attempt of any kind.

`ApplianceSelfIsolationGuard` wraps whatever isolation backend the shared
composition helper built. It does not reimplement the target policy: it calls
the existing `validate_isolation_target()` with the appliance's full address
set and, when a protected scope is configured, also refuses any address
outside that scope. Only when both pass is the wrapped backend called, so the
eligibility decision (`should_isolate()`, raw QRS >= threshold) and the
iptables commands are exactly as before.
"""
from __future__ import annotations

import logging
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional, Set

from enforcement.backends import IsolationBackend, IsolationOutcome
from enforcement.iptables_backend import validate_isolation_target

logger = logging.getLogger(__name__)

#: Linux `SIOCGIFADDR`: read an interface's primary IPv4 address.
_SIOCGIFADDR = 0x8915

#: Kernel interface-name limit (IFNAMSIZ - 1).
_IFNAMSIZ = 16

IoctlFn = Callable[[int, int, bytes], bytes]


def _default_ioctl() -> Optional[IoctlFn]:
    try:
        import fcntl  # Linux/Unix only; absent on Windows
    except ImportError:
        return None
    return fcntl.ioctl


def interface_ipv4_addresses(
    interface: Optional[str], ioctl_fn: Optional[IoctlFn] = None
) -> Set[str]:
    """The primary IPv4 address assigned to `interface`, as a set.

    Best-effort and never raises: no interface name, a platform without
    `fcntl` (Windows), an interface that does not exist, or one with no IPv4
    address all return an empty set, which simply means one fewer exclusion.
    `ioctl_fn` is injectable so this is testable without a real interface.
    """
    if not interface:
        return set()
    ioctl = ioctl_fn if ioctl_fn is not None else _default_ioctl()
    if ioctl is None:
        return set()

    request = struct.pack("256s", interface.encode()[: _IFNAMSIZ - 1])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            response = ioctl(sock.fileno(), _SIOCGIFADDR, request)
        address = socket.inet_ntoa(response[20:24])
    except Exception:  # noqa: BLE001 - best-effort; absence is handled by the caller
        logger.debug("Could not read an IPv4 address for interface %r.", interface, exc_info=True)
        return set()
    return {address}


def interface_index(interface: str, sys_class_net: Path = Path("/sys/class/net")) -> Optional[int]:
    """The kernel ifindex of `interface`, or None if it cannot be read.

    Read-only (one sysfs file). Used only to *notice* that an interface was
    re-created under the same name — never to act on it.
    """
    try:
        return int((sys_class_net / interface / "ifindex").read_text().strip())
    except (OSError, ValueError):
        return None


class ApplianceSelfIsolationGuard(IsolationBackend):
    """Refuses isolation targets the appliance must never isolate, then
    delegates everything else to the wrapped backend unchanged.

    Refused: any of the appliance's own addresses (via the existing
    `validate_isolation_target`), and — when `is_protected` is supplied — any
    address that is not a protected device. A refusal is reported as a normal
    not-enforced outcome; no iptables command is run for it.
    """

    def __init__(
        self,
        backend: IsolationBackend,
        local_addresses: Iterable[str],
        is_protected: Optional[Callable[[str], bool]] = None,
    ) -> None:
        self._backend = backend
        self._local_addresses = frozenset(str(address) for address in local_addresses)
        self._is_protected = is_protected
        self.backend_name = backend.backend_name
        self.enforcement_capable = backend.enforcement_capable

    @property
    def wrapped(self) -> IsolationBackend:
        return self._backend

    @property
    def local_addresses(self) -> frozenset:
        return self._local_addresses

    def _refusal(self, device_ip: str) -> Optional[str]:
        refusal = validate_isolation_target(device_ip, self._local_addresses)
        if refusal is not None:
            return refusal
        if self._is_protected is not None and not self._is_protected(device_ip):
            return (
                f"refusing to isolate {device_ip}: it is not a protected device in "
                "the configured protected scope"
            )
        return None

    def _refused(self, device_ip: str, risk_score: int, reason: str) -> IsolationOutcome:
        logger.warning("Isolation refused for %s: %s", device_ip, reason)
        return IsolationOutcome(
            device_ip=device_ip,
            risk_score=risk_score,
            requested_at=datetime.now(timezone.utc),
            requested=True,
            enforced=False,
            reason=reason,
            backend=self.backend_name,
            enforcement_capable=self.enforcement_capable,
        )

    def isolate(self, device_ip: str, risk_score: int) -> IsolationOutcome:
        refusal = self._refusal(device_ip)
        if refusal is not None:
            return self._refused(device_ip, risk_score, refusal)
        return self._backend.isolate(device_ip, risk_score)

    def restore(self, device_ip: str) -> IsolationOutcome:
        return self._backend.restore(device_ip)
