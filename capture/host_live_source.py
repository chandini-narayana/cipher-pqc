"""LiveCaptureSource — temporary, host-level Windows live packet capture.

This is a SEPARATE, additional capture implementation for the temporary
`run_live_demo.py` entry point only. It is NOT
`capture.live_source.LiveCaptureSource` — that class remains the
unmodified Phase 1 "documented scaffold" that backs CAPTURE_MODE=live
for main.py/run_api.py/run_demo.py (it still raises
LiveCaptureNotImplementedError immediately, unchanged). This module
exists alongside it so the frozen offline application's behavior is
never affected by this temporary live-capture work.

Scope (deliberately narrow — see run_live_demo.py's console disclaimer):
this captures packets visible to ONE selected host network interface
via Npcap/scapy, with `promisc=False`. It is host-level visibility into
this machine's own traffic, not Raspberry Pi monitor-mode capture, not
a full Wi-Fi network tap, and not promiscuous visibility into other
Wi-Fi clients.

Bounded and streaming: `read_packets()` yields RawPacket objects as
they arrive (via a background sniff thread bridged through a small
Queue), stopping when `timeout` seconds elapse or `packet_limit`
packets have been converted, whichever comes first — the same
CaptureSource shape `pipeline.runner.run_capture()` already consumes,
so no pipeline/runner.py change is needed to use this class.

DEVICE IDENTITY IS LIVE-MODE-SPECIFIC (see `_to_raw_packet`): the
downstream pipeline (pipeline/runner.py, unmodified) identifies a
"device" by `RawPacket.src_ip`. For an offline/network .pcap
(capture/offline_source.py, also unmodified), that is correct — each
distinct `src_ip` genuinely is a different IoT device on the monitored
network. Host-level Windows capture is a different topology: the
selected host interface is the ONE monitored endpoint, and every other
address it talks to is a remote peer, not a second monitored device.
Without correction, ordinary outbound web browsing makes every remote
server `src_ip` (for its response packets) look like a separate
"device" to the unmodified pipeline. This module resolves the
interface's own local IPv4 address once (`LiveCaptureSource`'s
`_local_ip`) and orients every captured packet around it before
`RawPacket` is ever constructed, so the local host is always
`src_ip` — never applied to, or shared with, OfflinePcapSource.
"""
from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator, List, Optional

from scapy.all import IP, TCP, UDP, conf, sniff

from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from utils.exceptions import CaptureError, ParsingError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_PACKET_LIMIT = 500

_SENTINEL = object()


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    """One entry from `list_interfaces()` — index, name, description,
    and IPv4 address (None if the interface has none) for one host
    network interface, as reported by scapy/Npcap."""

    index: int
    name: str
    description: str
    ipv4: Optional[str]


def list_interfaces() -> List[InterfaceInfo]:
    """List every network interface scapy/Npcap can see on this host,
    sorted by index. Never raises for an empty/unusual environment —
    an empty list is a valid (if useless) result."""
    infos = []
    for iface in conf.ifaces.values():
        ip = getattr(iface, "ip", None) or None
        if ip and ":" in ip:  # defensive: only ever report an IPv4-shaped address
            ip = None
        infos.append(
            InterfaceInfo(
                index=int(getattr(iface, "index", -1)),
                name=str(iface.name),
                description=str(getattr(iface, "description", "") or ""),
                ipv4=ip,
            )
        )
    return sorted(infos, key=lambda info: info.index)


def resolve_interface(name: str) -> InterfaceInfo:
    """Look up `name` among the host's interfaces by exact name match.

    Raises:
        CaptureError: if no interface named exactly `name` exists — the
            message lists every available interface name so the caller
            never has to guess (see `--list-interfaces`).
    """
    interfaces = list_interfaces()
    for info in interfaces:
        if info.name == name:
            return info

    available = ", ".join(repr(info.name) for info in interfaces) or "(none found)"
    raise CaptureError(
        f"Network interface {name!r} was not found. Available interfaces: {available}. "
        "Run `python run_live_demo.py --list-interfaces` to see the index, description, "
        "and IPv4 address for each one, then pass the exact name shown via --interface."
    )


def check_capture_backend_available() -> None:
    """Raise a clear, actionable CaptureError if scapy has no working
    packet-capture backend on this host. Never installs anything.

    Raises:
        CaptureError: if Npcap (or another libpcap-compatible backend)
            is not available to scapy.
    """
    if not getattr(conf, "use_pcap", False):
        raise CaptureError(
            "Live packet capture is unavailable: no working packet-capture backend "
            "was detected (Npcap does not appear to be installed, or scapy could not "
            "load it). Install Npcap from https://npcap.com/ and try again. CIPHER "
            "does not install anything automatically."
        )


class _CaptureFailure:
    """Internal queue payload wrapping an exception raised inside the
    background sniff thread, so it can be re-raised on the generator's
    own thread instead of being silently swallowed."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc


def _to_raw_packet(scapy_packet, local_ip: str) -> Optional[RawPacket]:
    """Convert one live-sniffed scapy packet into a RawPacket, oriented
    around `local_ip` (the selected interface's own IPv4 address) —
    see module docstring's "DEVICE IDENTITY IS LIVE-MODE-SPECIFIC" for
    why this differs from capture/offline_source.py's own conversion
    (kept as a separate copy, not a shared import, so that frozen
    module is never touched by this temporary addition).

    Filtering: only IP packets carrying a non-empty TCP/UDP payload,
    where `local_ip` is either the source or the destination, are
    converted. Anything else — no IP layer, no TCP/UDP transport, an
    empty payload (e.g. a bare SYN), or traffic between two other hosts
    that isn't to/from this interface — is skipped, not an error.

    Normalization: `RawPacket.src_ip` is always `local_ip` — the one
    monitored device in host-live mode.
      * Outbound (`ip_layer.src == local_ip`): fields pass through
        unchanged (src=local:src_port, dst=remote:dst_port) — this is
        already the shape the pipeline expects.
      * Inbound (`ip_layer.dst == local_ip`): fields are swapped so the
        local host is still `src_ip` — `src_port` becomes the local
        (destination) port and `dst_port` becomes the remote service
        port (e.g. an inbound `remote:443 -> local:53142` TLS response
        becomes `src_ip=local, src_port=53142, dst_ip=remote,
        dst_port=443`), so downstream port/protocol logic still sees
        443 as the service port. The payload bytes themselves are never
        altered — an inbound ServerHello/certificate still reaches
        fingerprinting exactly as captured.
    """
    if IP not in scapy_packet:
        return None

    ip_layer = scapy_packet[IP]
    if TCP in scapy_packet:
        transport = scapy_packet[TCP]
    elif UDP in scapy_packet:
        transport = scapy_packet[UDP]
    else:
        return None

    payload = bytes(transport.payload)
    if not payload:
        return None

    if ip_layer.src == local_ip:
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        src_port, dst_port = transport.sport, transport.dport
    elif ip_layer.dst == local_ip:
        src_ip, dst_ip = ip_layer.dst, ip_layer.src
        src_port, dst_port = transport.dport, transport.sport
    else:
        # Neither end of this packet is the monitored host (e.g.
        # broadcast/multicast traffic between two other LAN hosts) —
        # not a second monitored device, just not ours to report.
        return None

    timestamp = datetime.fromtimestamp(float(scapy_packet.time), tz=timezone.utc)

    try:
        return RawPacket(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(src_port),
            dst_port=int(dst_port),
            payload=payload,
            timestamp=timestamp,
        )
    except ValueError as exc:
        raise ParsingError(f"failed to parse live packet into RawPacket: {exc}") from exc


class LiveCaptureSource(CaptureSource):
    """Host-level Windows live capture, bounded by timeout and/or
    packet count. See module docstring for scope.

    `packets_captured` is a public counter, incremented once per
    RawPacket actually yielded (after filtering) — read it after fully
    draining `read_packets()` (e.g. after `run_capture()` returns) to
    report how many packets were captured.

    `local_ip` (the selected interface's own IPv4 address, resolved
    once at construction) is the one monitored device identity every
    captured packet is normalized around — see `_to_raw_packet`.

    Raises (from __init__, before any capture starts):
        CaptureError: if `interface` is empty, `timeout`/`packet_limit`
            are not positive, no capture backend (Npcap) is available,
            `interface` does not match a real host interface, or the
            matched interface has no IPv4 address (device-identity
            normalization has nothing to orient packets around).
    """

    def __init__(
        self,
        interface: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        packet_limit: int = DEFAULT_PACKET_LIMIT,
    ) -> None:
        if not interface:
            raise CaptureError(
                "A network interface name must be specified for live capture "
                "(see --list-interfaces)."
            )
        if timeout <= 0:
            raise CaptureError("timeout must be a positive number of seconds.")
        if packet_limit <= 0:
            raise CaptureError("packet_limit must be a positive integer.")

        check_capture_backend_available()
        info = resolve_interface(interface)
        if not info.ipv4:
            raise CaptureError(
                f"Interface {interface!r} has no IPv4 address assigned. Host-live "
                "capture identifies the monitored device by this interface's own "
                "IPv4 address (see --list-interfaces); choose an interface with one."
            )

        self._interface = interface
        self._local_ip = info.ipv4
        self._timeout = float(timeout)
        self._packet_limit = int(packet_limit)
        self.packets_captured = 0

    def read_packets(self) -> Iterator[RawPacket]:
        packet_queue: "queue.Queue[object]" = queue.Queue()
        stop_event = threading.Event()

        def _on_packet(scapy_packet) -> None:
            try:
                raw = _to_raw_packet(scapy_packet, self._local_ip)
            except ParsingError as exc:
                packet_queue.put(_CaptureFailure(exc))
                return
            if raw is not None:
                packet_queue.put(raw)

        def _run_sniff() -> None:
            try:
                sniff(
                    iface=self._interface,
                    timeout=self._timeout,
                    count=self._packet_limit,
                    store=False,
                    promisc=False,
                    prn=_on_packet,
                    stop_filter=lambda _pkt: stop_event.is_set(),
                )
            except Exception as exc:  # noqa: BLE001 - reported on the generator's thread instead
                packet_queue.put(_CaptureFailure(exc))
            finally:
                packet_queue.put(_SENTINEL)

        thread = threading.Thread(target=_run_sniff, name="cipher-live-sniff", daemon=True)
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
                        f"Live capture failed on interface {self._interface!r}: {item.exc}"
                    ) from item.exc

                self.packets_captured += 1
                logger.debug("Live packet captured (%d total).", self.packets_captured)
                yield item
        finally:
            stop_event.set()
            thread.join(timeout=self._timeout + 5.0)
