"""Protected-device attribution — which endpoint of a packet is the device
CIPHER is protecting.

The problem this solves. CIPHER's device identity has always been
`RawPacket.src_ip` (see `pipeline.runner._resolve_device`), which is exactly
right for an offline capture or a passive tap: each distinct source genuinely is
a different device. On a Raspberry Pi acting as the gateway for a protected
subnet it is right in only one direction. Traffic is bidirectional there, so:

    192.168.50.24 -> 93.184.216.34     src is the protected client   (correct)
    93.184.216.34 -> 192.168.50.24     src is a remote server        (wrong)

The second case makes every Internet peer a CIPHER "device": one browsing
client produces dozens of them, each with a real score, and — far worse — a
peer that reached raw QRS >= 7 would become the *isolation target*.

The fix is a labelling decision, nothing more. When a protected scope is
configured, this module answers "which address in this packet is the protected
device?" and the pipeline uses that answer as the identity. The packet itself is
never modified: `RawPacket` still records exactly what was on the wire, and the
inbound ServerHello/Certificate evidence that only travels server->client is
retained and simply filed under the client it concerns.

Why this is a pure function and nothing more. Scoring never consults an address
or a port: `fingerprint_packet()` takes only a payload (and by its own docstring
does not even accept a port), `port_risk_for_protocol()` keys off the detected
protocol, and `risk/`, `entropy/`, `fusion/` and `ml/` contain no reference to
`src_ip`, `dst_ip`, `src_port` or `dst_port`. So re-attributing a packet cannot
change a single score — it changes only whose score it is.

Deliberately dependency-free: stdlib `ipaddress` only, and no import of
capture/, ml/, hardware/, dashboard/ or enforcement/. That keeps it trivially
testable and keeps subnet policy out of every module that consumes the result.

**Opt-in.** Nothing constructs a scope by default. With no resolver configured,
`pipeline.runner` keeps `src_ip` identity byte-for-byte, so offline runs,
`run_demo.py`, `run_pi_live.py`, host-live capture and the research evaluation
are untouched.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


class InvalidProtectedScopeError(ValueError):
    """Raised for a protected network or excluded address that cannot be
    parsed.

    Raised at construction, so a bad configuration fails before any packet is
    processed rather than silently protecting nothing.
    """


def _parse_network(value: object) -> ipaddress.IPv4Network:
    text = str(value).strip()
    if not text:
        raise InvalidProtectedScopeError("a protected network must not be empty")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise InvalidProtectedScopeError(
            f"{text!r} is not a valid IPv4 network in CIDR form (for example "
            "192.168.50.0/24)"
        ) from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise InvalidProtectedScopeError(
            f"{text!r} is not IPv4: protected-device attribution is IPv4-only, "
            "matching CIPHER's IPv4 device identity"
        )
    return network


def _parse_address(value: object) -> Optional[ipaddress.IPv4Address]:
    """Parse one excluded address, or None if it is not a usable IPv4 address.

    Lenient on purpose: the excluded set is populated from best-effort host
    discovery (`enforcement.iptables_backend.local_ipv4_addresses()`), which may
    legitimately return an IPv6 address or nothing at all. An unusable entry
    means one fewer exclusion, never a startup failure.
    """
    text = str(value).strip()
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        logger.debug("Ignoring unparseable excluded address %r.", text)
        return None
    if not isinstance(address, ipaddress.IPv4Address):
        logger.debug("Ignoring non-IPv4 excluded address %r.", text)
        return None
    return address


def _is_network_or_broadcast(
    address: ipaddress.IPv4Address, network: ipaddress.IPv4Network
) -> bool:
    """Whether `address` is `network`'s network or broadcast address.

    /31 and /32 networks have no such reserved addresses (RFC 3021), so every
    address in them is a host.
    """
    if network.prefixlen >= 31:
        return False
    return address in (network.network_address, network.broadcast_address)


class ProtectedScope:
    """The set of networks whose devices CIPHER is protecting, plus the
    addresses that must never be treated as protected devices.

    `excluded_addresses` exists for one specific, important case: on the target
    topology the appliance's own address (192.168.50.1) is *inside* the
    protected /24, so a naive membership test would make the Pi a protected
    device of itself and score its own DNS/DHCP replies. Excluding it is
    checked first, before any membership test.

    Raises:
        InvalidProtectedScopeError: if no network is given, or any network is
            not a valid IPv4 CIDR.
    """

    __slots__ = ("_networks", "_excluded")

    def __init__(
        self,
        networks: Sequence[object],
        excluded_addresses: Iterable[object] = (),
    ) -> None:
        parsed = tuple(_parse_network(network) for network in networks)
        if not parsed:
            raise InvalidProtectedScopeError(
                "at least one protected network must be given"
            )
        self._networks: Tuple[ipaddress.IPv4Network, ...] = parsed
        self._excluded: Set[ipaddress.IPv4Address] = {
            address
            for address in (_parse_address(value) for value in excluded_addresses)
            if address is not None
        }

    @property
    def networks(self) -> Tuple[str, ...]:
        return tuple(str(network) for network in self._networks)

    @property
    def excluded_addresses(self) -> Tuple[str, ...]:
        return tuple(sorted(str(address) for address in self._excluded))

    def is_protected(self, ip: object) -> bool:
        """Whether `ip` is a protected device address.

        False for an excluded (self) address, for anything outside every
        configured network, for anything that is not a parseable IPv4
        address — a malformed or IPv6 value is never protected rather than
        raising into the capture loop — and for the network or broadcast
        address of any configured network that contains it. A subnet-directed
        broadcast such as 192.168.50.255 is *inside* 192.168.50.0/24, so a
        plain membership test would make it a device (and, at QRS >= 7, an
        isolation target); it is never a host.
        """
        address = _parse_address(ip)
        if address is None:
            return False
        if address in self._excluded:
            return False
        containing = [network for network in self._networks if address in network]
        if not containing:
            return False
        return not any(_is_network_or_broadcast(address, network) for network in containing)

    def resolve(self, src_ip: object, dst_ip: object) -> Optional[str]:
        """The protected device for this packet, or None if there is none.

        The frozen rule, in this order:

          * src protected, dst not        -> src   (outbound; unchanged from
            CIPHER's historic behaviour)
          * src not protected, dst        -> dst   (inbound; the fix)
          * both protected                -> src   (lab-to-lab: the sender is
            the actor, and one deterministic answer per packet is required.
            Both devices are still assessed across a conversation, since both
            send.)
          * neither protected             -> None  (not about a protected
            device at all; the caller skips the packet)

        The Pi's own address is excluded by `is_protected`, so `Pi -> protected`
        resolves to the protected destination and `Internet -> Pi` resolves to
        None. Global broadcast and multicast destinations are outside every
        protected network, and a protected network's own network and
        broadcast addresses are never protected (see `is_protected`), so none
        of them can become an identity.

        Returns the address as the string the caller received, so the identity
        is byte-identical to what the packet carried — never a reformatted or
        normalised form.
        """
        src_protected = self.is_protected(src_ip)
        dst_protected = self.is_protected(dst_ip)

        if src_protected:
            return str(src_ip)
        if dst_protected:
            return str(dst_ip)
        return None


def parse_protected_networks(raw: Optional[str]) -> Tuple[str, ...]:
    """Split a comma-separated CIDR list into its parts, validating each.

    Returns an empty tuple for None or an all-whitespace value, which the
    caller reads as "no protected scope configured" — i.e. legacy behaviour.

    Raises:
        InvalidProtectedScopeError: if any non-empty part is not a valid IPv4
            CIDR, so a typo fails at startup rather than protecting nothing.
    """
    if raw is None:
        return ()
    parts = [part.strip() for part in str(raw).split(",")]
    present = [part for part in parts if part]
    if not present:
        return ()
    return tuple(str(_parse_network(part)) for part in present)
