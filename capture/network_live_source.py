"""NetworkLiveCaptureSource — live capture on a Linux/Raspberry-Pi
interface that preserves the TRUE source device identity.

Why this is a separate class from `capture.host_live_source.LiveCaptureSource`
rather than a generalization of it: the two have *opposite, irreconcilable*
device-identity policies, and only one of them can be correct per topology.

  * `host_live_source` monitors ONE endpoint — this machine. Every other
    address it sees is a remote peer, not a monitored device, so it
    deliberately normalizes `RawPacket.src_ip` to the interface's own
    IPv4 address and discards any packet where neither end is local.
    That is correct there and must not change.
  * This module monitors a NETWORK PATH on which many devices are
    visible. Each distinct source address genuinely *is* a different
    device. Normalizing here would be actively dangerous: the pipeline
    identifies a device by `RawPacket.src_ip`, and a later Linux
    enforcement backend will isolate exactly that address. An assessed
    identity that does not match the enforced identity is unacceptable
    — so this module never rewrites, swaps or normalizes an address.

Folding both policies into one class would mean a single capture source
whose device-identity semantics flip on a constructor flag, with the
Windows demo one wrong default away from isolating the wrong host. Two
small classes behind the same `CaptureSource` interface is the safer
shape, and nothing downstream can tell them apart.

Scope, and what this deliberately does NOT do: this reads frames that
are already IP-visible on the named interface. It performs no
WPA/WPA2/WPA3 decryption, no deauthentication, and no credential
capture. A monitor-mode Radiotap/802.11 frame is processed only when it
already carries a decodable IP layer; a protected frame that exposes no
IP payload is counted and skipped, never attacked. Use it only on an
interface where the traffic is legitimately available to this host — a
controlled test network, an authorized mirror/tap, or a path this host
is explicitly authorized to observe.

Everything downstream is unchanged: this yields the same `RawPacket`
contract as `OfflinePcapSource`, so `CaptureSource -> RawPacket ->
fingerprinting -> QRS -> Isolation Forest -> fusion -> isolation
decision` runs exactly as it already does. No pipeline change, no
registry, no persistence.
"""
from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, Optional

from scapy.all import IP, TCP, UDP, conf, sniff

from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from utils.exceptions import CaptureError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_PACKET_LIMIT = 1000

_SENTINEL = object()


@dataclass
class CaptureCounters:
    """Plain per-run counters for one live capture, following the
    existing single-public-counter precedent in
    `host_live_source.LiveCaptureSource.packets_captured` — four ints,
    no telemetry subsystem, no persistence.

    `seen` counts every frame the capture backend handed us;
    `yielded` counts RawPackets actually produced; `skipped_non_ip`
    counts frames with no IP layer at all (ARP, 802.11 management,
    protected frames with no decodable IP, IPv6); `skipped_no_transport`
    counts IP frames with no TCP/UDP layer or an empty payload (a bare
    SYN carries nothing to analyze); `parse_failures` counts frames
    whose fields an IP layer claimed to have but `RawPacket` rejected.
    """

    seen: int = 0
    yielded: int = 0
    skipped_non_ip: int = 0
    skipped_no_transport: int = 0
    parse_failures: int = 0

    def summary(self) -> str:
        return (
            f"seen={self.seen}, yielded={self.yielded}, "
            f"skipped_non_ip={self.skipped_non_ip}, "
            f"skipped_no_transport={self.skipped_no_transport}, "
            f"parse_failures={self.parse_failures}"
        )


class _CaptureFailure:
    """Internal queue payload wrapping an exception raised inside the
    background sniff thread, so it is re-raised on the generator's own
    thread instead of being silently swallowed. Same approach as
    host_live_source — a capture *backend* failure (bad interface, no
    permission) is fatal and must surface; a single unusable *frame*
    never is."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc


def interface_exists(name: str) -> bool:
    """Whether `name` appears among the interfaces scapy can enumerate.

    Returns True when the enumeration is empty, so a host where scapy
    reports nothing useful is not falsely told its interface is missing;
    the real failure then surfaces from the capture backend itself.
    """
    try:
        names = {str(iface.name) for iface in conf.ifaces.values()}
    except Exception:  # noqa: BLE001 - enumeration is best-effort only
        return True
    if not names:
        return True
    return name in names


def available_interface_names() -> list[str]:
    """Interface names scapy can enumerate, sorted. Best-effort: returns
    an empty list rather than raising on an unusual environment."""
    try:
        return sorted(str(iface.name) for iface in conf.ifaces.values())
    except Exception:  # noqa: BLE001 - enumeration is best-effort only
        return []


class NetworkLiveCaptureSource(CaptureSource):
    """Live capture on one explicitly-named network interface, preserving
    each packet's real source address as its device identity.

    The interface is always supplied by the caller — no name is defaulted
    or hardcoded here, so this module knows nothing about `wlan0`,
    `wlan1` or `eth0` and cannot disturb any management interface.

    Bounded by `timeout` seconds and `packet_limit` converted packets,
    whichever comes first, and streaming: packets are yielded as they
    arrive via a background sniff thread bridged through a small Queue.

    `counters` (a CaptureCounters) is public and may be read after the
    iterator is drained to report seen/yielded/skipped totals.

    Raises (from __init__, before any capture starts):
        CaptureError: if `interface` is empty/blank, `timeout` or
            `packet_limit` is not positive, or `interface` does not match
            any interface scapy can enumerate.

    Raises (from read_packets):
        CaptureError: if the capture backend itself fails — a
            nonexistent interface, a permission error (live capture
            normally needs root or CAP_NET_RAW), or any other sniff
            failure. Individual unusable frames never raise.
    """

    def __init__(
        self,
        interface: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        packet_limit: int = DEFAULT_PACKET_LIMIT,
        bpf_filter: Optional[str] = None,
    ) -> None:
        if not interface or not interface.strip():
            raise CaptureError(
                "A network interface name must be specified for live capture "
                "(pass the exact interface name, e.g. via --interface)."
            )
        if timeout <= 0:
            raise CaptureError("timeout must be a positive number of seconds.")
        if packet_limit <= 0:
            raise CaptureError("packet_limit must be a positive integer.")
        if not interface_exists(interface):
            available = ", ".join(repr(n) for n in available_interface_names()) or "(none found)"
            raise CaptureError(
                f"Network interface {interface!r} was not found. Available interfaces: "
                f"{available}."
            )

        self._interface = interface
        self._timeout = float(timeout)
        self._packet_limit = int(packet_limit)
        self._bpf_filter = bpf_filter
        self.counters = CaptureCounters()

    @property
    def interface(self) -> str:
        return self._interface

    def read_packets(self) -> Iterator[RawPacket]:
        packet_queue: "queue.Queue[object]" = queue.Queue()
        stop_event = threading.Event()

        def _on_packet(scapy_packet) -> None:
            # Runs on the sniff thread. Must never raise: a single bad
            # frame may not tear down the capture loop.
            try:
                raw = self._to_raw_packet(scapy_packet)
            except Exception:  # noqa: BLE001 - one unusable frame is never fatal
                self.counters.parse_failures += 1
                logger.debug("Skipping an unparseable captured frame.", exc_info=True)
                return
            if raw is not None:
                packet_queue.put(raw)

        def _run_sniff() -> None:
            try:
                sniff_kwargs = {
                    "iface": self._interface,
                    "timeout": self._timeout,
                    "count": self._packet_limit,
                    "store": False,
                    "prn": _on_packet,
                    "stop_filter": lambda _pkt: stop_event.is_set(),
                }
                if self._bpf_filter:
                    sniff_kwargs["filter"] = self._bpf_filter
                sniff(**sniff_kwargs)
            except Exception as exc:  # noqa: BLE001 - reported on the generator's thread
                packet_queue.put(_CaptureFailure(exc))
            finally:
                packet_queue.put(_SENTINEL)

        thread = threading.Thread(target=_run_sniff, name="cipher-network-sniff", daemon=True)
        thread.start()

        try:
            while True:
                try:
                    item = packet_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                if item is _SENTINEL:
                    break
                if isinstance(item, _CaptureFailure):
                    raise CaptureError(
                        f"Live capture failed on interface {self._interface!r}: {item.exc}. "
                        "Live capture requires an existing interface and sufficient "
                        "privileges (root or CAP_NET_RAW)."
                    ) from item.exc

                self.counters.yielded += 1
                yield item
        finally:
            stop_event.set()
            thread.join(timeout=self._timeout + 5.0)
            logger.info(
                "Live capture on %s finished: %s", self._interface, self.counters.summary()
            )

    def _to_raw_packet(self, scapy_packet) -> Optional[RawPacket]:
        """Convert one captured frame into a RawPacket, or None if the
        frame carries nothing this pipeline can analyze.

        Identity is passed through verbatim: `src_ip` is the packet's own
        IP source and `dst_ip` its own IP destination, with ports and
        payload bytes untouched. No address is rewritten, swapped or
        normalized to this host — see the module docstring for why that
        is a correctness requirement and not a preference.

        A Radiotap/802.11 frame needs no special handling: scapy's layer
        lookup finds an IP layer if the frame genuinely exposes one, and
        a protected frame that does not is simply counted as non-IP and
        skipped. No decryption is attempted.
        """
        self.counters.seen += 1

        if IP not in scapy_packet:
            # No IP layer at all: ARP, 802.11 management/control frames,
            # protected frames with no decodable IP payload, IPv6, or
            # any other out-of-scope frame. Expected, never an error.
            self.counters.skipped_non_ip += 1
            return None

        ip_layer = scapy_packet[IP]
        if TCP in scapy_packet:
            transport = scapy_packet[TCP]
        elif UDP in scapy_packet:
            transport = scapy_packet[UDP]
        else:
            self.counters.skipped_no_transport += 1
            return None

        payload = bytes(transport.payload)
        if not payload:
            # A bare SYN/ACK carries nothing for entropy or
            # fingerprinting — same rule OfflinePcapSource applies.
            self.counters.skipped_no_transport += 1
            return None

        timestamp = self._packet_timestamp(scapy_packet)

        try:
            return RawPacket(
                src_ip=str(ip_layer.src),
                dst_ip=str(ip_layer.dst),
                src_port=int(transport.sport),
                dst_port=int(transport.dport),
                payload=payload,
                timestamp=timestamp,
            )
        except (ValueError, TypeError) as exc:
            # A malformed frame whose IP/transport fields RawPacket
            # rejects. Counted and skipped — the capture loop continues.
            self.counters.parse_failures += 1
            logger.debug("Skipping a captured frame RawPacket rejected: %s", exc)
            return None

    @staticmethod
    def _packet_timestamp(scapy_packet) -> datetime:
        """The frame's own capture time, falling back to now if the
        backend did not provide a usable one (never a reason to drop an
        otherwise-valid packet)."""
        try:
            return datetime.fromtimestamp(float(scapy_packet.time), tz=timezone.utc)
        except (AttributeError, TypeError, ValueError, OSError, OverflowError):
            return datetime.now(timezone.utc)
