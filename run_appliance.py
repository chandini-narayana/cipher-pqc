"""run_appliance.py — CIPHER appliance mode: continuous live capture with
the dashboard available while it runs.

A sixth composition root, alongside main.py (offline, run-and-exit),
run_api.py (API-only dev server), run_demo.py (integrated OFFLINE demo),
run_live_demo.py (host-level Windows live demo) and run_pi_live.py (bounded
Pi live diagnostic). **None of those is modified or replaced**, and each
keeps its own semantics, flags and exit codes.

Why a separate entry point: appliance mode is a genuinely different
topology — live capture plus optional enforcement plus optional hardware
output plus a server, running continuously. run_demo.py is documented and
tested as the offline presentation demo, and run_pi_live.py as a bounded
run-and-exit diagnostic; overloading either with a long-running server
would put two incompatible lifecycles behind one flag. This file composes
their existing pieces instead of duplicating them.

Shape — one process, two threads:

    main thread   : Flask serves /api/* and the compiled web/ SPA
    worker thread : bounded capture cycles -> run_capture -> publish state

Nothing about CIPHER's assessment or enforcement changes. Each cycle is one
ordinary `pipeline.runner.run_capture()` call, so QRS, Isolation Forest,
fusion, the raw-QRS >= 7 isolation rule, the iptables backend and report
signing are all untouched. **Physical isolation stays immediate and
per-packet** inside that call — it never waits for a cycle boundary or for
the dashboard to poll — and so do the OLED and LED updates. The cycle
boundary governs only when the dashboard's snapshot is replaced.

Safe defaults are preserved exactly: enforcement is `noop`, the display is
`none` and the LEDs are `none` unless each is explicitly selected, and
`iptables`/`oled`/`gpio` all remain Linux-guarded.

Usage:

    python run_appliance.py --interface eth0
    python run_appliance.py --interface eth0 --cycle-seconds 5
    python run_appliance.py --interface eth0 --enforcement iptables \\
        --display oled --leds gpio --led-pins 17,27,22

Raspberry Pi boot/systemd installation is deliberately NOT part of this
file: it starts and stops like any other program.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from dataclasses import replace
from pathlib import Path
from typing import Optional, Sequence

from appliance.interface_info import (
    ApplianceSelfIsolationGuard,
    interface_index,
    interface_ipv4_addresses,
)
from appliance.output_gate import HardwareOutputGate
from appliance.worker import (
    DEFAULT_CYCLE_SECONDS,
    MIN_CYCLE_SECONDS,
    ApplianceCaptureWorker,
)
from capture.network_live_source import DEFAULT_PACKET_LIMIT, NetworkLiveCaptureSource
from config.constants import APP_NAME, APP_VERSION, DEFAULT_RISK_ISOLATION_THRESHOLD
from config.settings import load_settings
from dashboard import ApplicationStateStore, create_app
from dashboard.spa import MissingWebBuildError, register_spa, validate_web_build
from enforcement.iptables_backend import local_ipv4_addresses
from hardware import InvalidPinConfigurationError
from ml.loading import load_anomaly_detector
from pipeline.device_resolution import (
    InvalidProtectedScopeError,
    ProtectedScope,
    parse_protected_networks,
)
from pipeline.runner import run_capture
from signing import load_or_create_keypair
from utils.exceptions import CipherError
from utils.logging_setup import configure_logging

# The Pi diagnostic entry point already owns the composition helpers for
# the isolation backend, the OLED, the LEDs and the observer fan-out,
# including every Linux guard and safe default. They are imported rather
# than copied so there is exactly ONE implementation of those safety
# decisions: a change there applies here automatically, and the two entry
# points can never disagree about when real enforcement or real hardware is
# permitted.
from run_pi_live import (  # noqa: E402 - imported for reuse, see comment above
    _build_assessment_observer,
    _build_isolation_backend,
    _build_status_display,
    _build_status_indicator,
    _safe_display,
)

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent / "web"

#: The lowest raw QRS that may authorize physical isolation. A configured
#: threshold below this is refused at startup, never clamped: raw QRS >= 7 is
#: the project's security rule, and an environment variable or `.env` must
#: not be able to quietly weaken it.
MIN_ISOLATION_THRESHOLD = DEFAULT_RISK_ISOLATION_THRESHOLD


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_appliance.py",
        description=(
            "CIPHER appliance mode: continuous live capture with the dashboard "
            "and REST API available while it runs. Enforcement and hardware "
            "output are off unless explicitly selected."
        ),
    )
    parser.add_argument(
        "--interface",
        default=None,
        help=(
            "Exact interface name to capture on, e.g. eth0. May also be given as "
            "the PI_CAPTURE_INTERFACE environment variable. Required: no "
            "interface is ever defaulted."
        ),
    )
    parser.add_argument(
        "--cycle-seconds",
        type=float,
        default=DEFAULT_CYCLE_SECONDS,
        help=(
            f"Length of each bounded capture cycle (default: {DEFAULT_CYCLE_SECONDS:g}s, "
            f"minimum: {MIN_CYCLE_SECONDS:g}s). This is how often the dashboard's "
            "snapshot is replaced; it does NOT delay physical isolation, which "
            "stays immediate and per-packet."
        ),
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=DEFAULT_PACKET_LIMIT,
        help=(
            "Maximum packets per cycle; a cycle ends at whichever bound is "
            f"reached first (default: {DEFAULT_PACKET_LIMIT})."
        ),
    )
    parser.add_argument(
        "--enforcement",
        choices=("noop", "iptables"),
        default=None,
        help=(
            "Enforcement backend. 'noop' (the default) records isolation decisions "
            "without touching any firewall. 'iptables' installs real DROP rules "
            "for isolated devices; it requires Linux and root (or CAP_NET_ADMIN) "
            "and is never selected implicitly. Also CIPHER_ENFORCEMENT."
        ),
    )
    parser.add_argument(
        "--display",
        choices=("none", "oled"),
        default=None,
        help=(
            "Status display. 'none' (the default) renders nothing. 'oled' drives an "
            "SSD1306 panel over I2C on a Raspberry Pi. Also CIPHER_DISPLAY."
        ),
    )
    parser.add_argument(
        "--leds",
        choices=("none", "gpio"),
        default=None,
        help=(
            "Status LEDs. 'none' (the default) drives nothing. 'gpio' lights one of "
            "three LEDs for the assessed risk category. Requires --led-pins. "
            "Also CIPHER_LEDS."
        ),
    )
    parser.add_argument(
        "--led-pins",
        default=None,
        help=(
            "Three comma-separated BCM pin numbers for the green, amber and red "
            "LEDs, e.g. --led-pins 17,27,22. Required by --leds gpio. "
            "Also CIPHER_LED_PINS."
        ),
    )
    parser.add_argument(
        "--protected-subnet",
        default=None,
        help=(
            "Comma-separated IPv4 CIDRs whose devices CIPHER is protecting, e.g. "
            "192.168.50.0/24. When set, a packet is attributed to its protected "
            "endpoint, so an inbound server-to-client packet counts as the client "
            "rather than making the remote server a CIPHER device. Unset (the "
            "default) keeps the historic source-address identity exactly. May "
            "also be given as the CIPHER_PROTECTED_SUBNETS environment variable."
        ),
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        default=None,
        help="Optional BPF capture filter passed through to the capture backend.",
    )
    return parser.parse_args(argv)


def _print_banner(
    interface: str,
    cycle_seconds: float,
    enforcement: str,
    display_mode: str,
    led_mode: str,
    protected: str,
    host: str,
    port: int,
    threshold: int = DEFAULT_RISK_ISOLATION_THRESHOLD,
) -> None:
    print("")
    print(f"{APP_NAME} v{APP_VERSION} - appliance mode")
    print("-" * 62)
    print(f"Interface:     {interface}")
    print(f"Cycle:         {cycle_seconds:g}s bounded capture cycles, continuous")
    if enforcement == "iptables":
        print(f"Enforcement:   IPTABLES - real DROP rules for raw QRS >= {threshold}")
    else:
        print(
            f"Enforcement:   NONE - isolation decisions (raw QRS >= {threshold}) are "
            "recorded, never enforced"
        )
    print(f"Display:       {display_mode}    LEDs: {led_mode}")
    print(f"Protected:     {protected or 'not configured - source-address identity'}")
    print("Decryption:    NONE - no WPA/WPA2/WPA3 decryption, no deauthentication")
    print("Isolation is immediate and per-packet; the cycle only governs when the")
    print("dashboard snapshot is replaced.")
    print("-" * 62)
    print(f"Dashboard:     http://{host}:{port}")
    print("")


def _build_protected_scope(
    raw: Optional[str], extra_excluded: Sequence[str] = ()
) -> Optional[ProtectedScope]:
    """Build the protected scope, or None when none is configured.

    None means legacy behaviour: `run_capture` keeps its historic `src_ip`
    identity, so nothing changes for any existing run. No subnet is ever
    defaulted — the protected network is a deployment fact, like the interface
    name and the GPIO pins, and guessing it would silently hide real clients or
    protect the wrong ones.

    The appliance's own addresses are excluded, because on the intended
    topology the Pi's address (for example 192.168.50.1) is *inside* the
    protected /24 and a plain membership test would make the appliance a
    protected device of itself. `local_ipv4_addresses()` is reused read-only
    from the enforcement layer, which already needed exactly this answer to
    refuse isolating the host; discovery there is best-effort, so an empty
    result simply means one fewer exclusion.

    That discovery resolves the hostname, which on a stock Debian image often
    yields only 127.0.1.1 and misses the lab address. `extra_excluded` carries
    the capture interface's own IPv4 address(es), read directly from the
    interface by `main()`, so the appliance's address on the protected network
    is excluded regardless of how the hostname resolves.
    """
    networks = parse_protected_networks(raw)
    if not networks:
        return None

    scope = ProtectedScope(
        networks, excluded_addresses=set(local_ipv4_addresses()) | set(extra_excluded)
    )
    logger.info(
        "Protected-device attribution enabled for %s (excluding this host's own "
        "address(es): %s).",
        ", ".join(scope.networks),
        ", ".join(scope.excluded_addresses) or "none discovered",
    )
    return scope


def _guard_against_self_isolation(backend, interface_addresses, protected_scope):
    """Wrap an enforcing backend so it can never isolate the appliance itself
    (or, with a protected scope, anything outside it).

    The guard reuses `validate_isolation_target` with the union of the
    hostname-derived addresses and the capture interface's own address(es), so
    the iptables refusal sees the same self-addresses as the protected scope.
    A non-enforcing backend (NoOp) is returned unchanged: it can isolate
    nothing, and leaving it as-is keeps its behaviour byte-for-byte.
    """
    if not backend.enforcement_capable:
        return backend
    local_addresses = set(local_ipv4_addresses()) | set(interface_addresses)
    logger.info(
        "Isolation will refuse this appliance's own address(es): %s.",
        ", ".join(sorted(local_addresses)) or "none discovered",
    )
    return ApplianceSelfIsolationGuard(
        backend,
        local_addresses,
        is_protected=protected_scope.is_protected if protected_scope else None,
    )


def _build_source_factory(
    interface: str, cycle_seconds: float, packet_limit: int, bpf_filter: Optional[str]
):
    """A factory that builds a FRESH capture source for every cycle.

    Fresh on purpose: `NetworkLiveCaptureSource.counters` are created in its
    constructor and accumulate across `read_packets()` calls, so reusing one
    source would report growing run totals rather than per-cycle figures.
    """

    def _factory() -> NetworkLiveCaptureSource:
        return NetworkLiveCaptureSource(
            interface=interface,
            timeout=cycle_seconds,
            packet_limit=packet_limit,
            bpf_filter=bpf_filter,
        )

    return _factory


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    interface = args.interface or os.environ.get("PI_CAPTURE_INTERFACE") or None
    if not interface:
        print(
            "No interface specified. Pass --interface <name> (or set "
            "PI_CAPTURE_INTERFACE).",
            file=sys.stderr,
        )
        return 2

    enforcement_mode = (
        args.enforcement or os.environ.get("CIPHER_ENFORCEMENT") or "noop"
    ).lower()
    if enforcement_mode not in ("noop", "iptables"):
        print(
            f"Unrecognized enforcement mode {enforcement_mode!r}. "
            "Expected 'noop' or 'iptables'.",
            file=sys.stderr,
        )
        return 2

    display_mode = (args.display or os.environ.get("CIPHER_DISPLAY") or "none").lower()
    if display_mode not in ("none", "oled"):
        print(
            f"Unrecognized display mode {display_mode!r}. Expected 'none' or 'oled'.",
            file=sys.stderr,
        )
        return 2

    led_mode = (args.leds or os.environ.get("CIPHER_LEDS") or "none").lower()
    if led_mode not in ("none", "gpio"):
        print(
            f"Unrecognized LED mode {led_mode!r}. Expected 'none' or 'gpio'.",
            file=sys.stderr,
        )
        return 2
    led_pins_raw = args.led_pins or os.environ.get("CIPHER_LED_PINS")

    if args.cycle_seconds < MIN_CYCLE_SECONDS:
        print(
            f"--cycle-seconds must be at least {MIN_CYCLE_SECONDS:g}. A shorter cycle "
            "would reuse a device's report filename within the same second and "
            "overwrite its previous signed report.",
            file=sys.stderr,
        )
        return 2

    # The capture interface's own address: on the AP topology this is the
    # appliance's address on the protected network (e.g. wlan1's 192.168.50.1).
    # Read-only; empty off Linux or if the interface has no IPv4 address.
    interface_addresses = interface_ipv4_addresses(interface)

    protected_raw = args.protected_subnet or os.environ.get("CIPHER_PROTECTED_SUBNETS")
    try:
        protected_scope = _build_protected_scope(protected_raw, interface_addresses)
    except InvalidProtectedScopeError as exc:
        print(f"Invalid protected subnet: {exc}", file=sys.stderr)
        return 2

    settings = load_settings()
    if settings.risk_isolation_threshold < MIN_ISOLATION_THRESHOLD:
        print(
            f"Refusing to start: the configured isolation threshold is "
            f"{settings.risk_isolation_threshold} (RISK_ISOLATION_THRESHOLD), but "
            f"{MIN_ISOLATION_THRESHOLD} is the minimum permitted physical-isolation "
            f"threshold. Only a raw deterministic QRS >= {MIN_ISOLATION_THRESHOLD} may "
            "authorize isolation.",
            file=sys.stderr,
        )
        return 2
    configure_logging(settings)
    settings = replace(settings, capture_mode="live", live_interface=interface)

    # Validated FIRST, before any capture or hardware work: a missing or
    # incomplete web/ build must fail in under a second rather than after a
    # capture cycle has already run.
    try:
        validate_web_build(WEB_DIR)
    except MissingWebBuildError as exc:
        logger.error("Web build validation failed.", exc_info=True)
        print(f"{exc}", file=sys.stderr)
        return 1

    _print_banner(
        interface,
        args.cycle_seconds,
        enforcement_mode,
        display_mode,
        led_mode,
        ", ".join(protected_scope.networks) if protected_scope else "",
        settings.flask_host,
        settings.flask_port,
        settings.risk_isolation_threshold,
    )

    # Optional output devices, built and started once for the whole run.
    display = _build_status_display(display_mode)
    try:
        indicator = _build_status_indicator(led_mode, led_pins_raw)
    except InvalidPinConfigurationError as exc:
        # The display already exists at this point, so release it before
        # bailing out rather than leaving a constructed device behind. Today's
        # SSD1306 adapter acquires nothing until start(), so nothing is
        # actually held — but that is its implementation detail, not a promise
        # of the StatusDisplay contract, and an abandoned device on an error
        # path is the kind of thing that only becomes a bug later.
        _safe_display("shutdown after LED configuration error", display.close)
        print(f"Invalid LED configuration: {exc}", file=sys.stderr)
        return 2

    _safe_display("start", display.start)
    _safe_display("ready frame", display.show_ready, interface, enforcement_mode)
    _safe_display("LED start", indicator.start)
    _safe_display("LED ready state", indicator.show_ready)

    try:
        isolation_backend = _guard_against_self_isolation(
            _build_isolation_backend(enforcement_mode), interface_addresses, protected_scope
        )
        # Loaded once for the whole run, never per cycle: the detector and
        # the keypair are expensive and entirely reusable.
        anomaly_detector = load_anomaly_detector(settings.model_path)
        public_key, secret_key = load_or_create_keypair(settings.signing_key_path)
    except CipherError as exc:
        logger.error("Appliance startup failed.", exc_info=True)
        print(f"Appliance startup failed: {exc}", file=sys.stderr)
        _safe_display("shutdown", display.close)
        _safe_display("LED shutdown", indicator.close)
        return 1

    # An empty snapshot so the dashboard is reachable immediately, before
    # the first cycle has produced anything.
    store = ApplicationStateStore()
    app = create_app(store, settings)
    register_spa(app, WEB_DIR)

    # One barrier owns every hardware write from here on: the worker writes
    # only through it, and shutdown releases the devices only through it.
    output_gate = HardwareOutputGate(
        observer=_build_assessment_observer(display, indicator),
        close_calls=[("shutdown", display.close), ("LED shutdown", indicator.close)],
        safe_call=_safe_display,
    )

    worker = ApplianceCaptureWorker(
        store=store,
        source_factory=_build_source_factory(
            interface, args.cycle_seconds, args.packet_limit, args.bpf_filter
        ),
        run_capture_fn=run_capture,
        capture_kwargs={
            "anomaly_detector": anomaly_detector,
            "public_key": public_key,
            "secret_key": secret_key,
            "isolation_backend": isolation_backend,
            "risk_isolation_threshold": settings.risk_isolation_threshold,
            # Per-packet and immediate, exactly as in run_pi_live: the OLED
            # and LEDs update as devices are assessed, not at cycle end. The
            # gate wraps that observer unchanged; it only ensures the worker
            # cannot be mid-write when shutdown releases the hardware.
            "assessment_observer": output_gate.observe,
            # Identity only, and only when a scope was explicitly configured.
            # None keeps run_capture's historic src_ip behaviour untouched.
            "device_resolver": protected_scope.resolve if protected_scope else None,
        },
        cycle_seconds=args.cycle_seconds,
        # Once per cycle, after the dashboard snapshot is published: keep an
        # enforced isolation on the OLED and LEDs, since per-packet frames are
        # produced before isolation state exists and would overwrite it.
        on_cycle_published=lambda state: output_gate.hold_isolated(state.list_assessments()),
        # Observability only: warn if the capture interface is re-created.
        interface_index_fn=lambda: interface_index(interface),
    )

    _install_signal_handlers(worker.stop_event)
    thread = worker.start_thread()

    try:
        app.run(
            host=settings.flask_host,
            port=settings.flask_port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        print("\nShutting down.", file=sys.stderr)
    finally:
        _shutdown(worker, thread, output_gate, args.cycle_seconds)

    return 0


def _install_signal_handlers(stop_event: threading.Event) -> None:
    """Ask the worker to stop on SIGTERM/SIGINT.

    Best-effort: `signal.signal` only works on the main thread of the main
    interpreter, so a caller that invokes `main()` from elsewhere (a test,
    for instance) simply gets no handler rather than an error.
    """

    def _handle(_signum, _frame):
        stop_event.set()
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handle)
        except (ValueError, OSError):  # pragma: no cover - non-main-thread caller
            logger.debug("Could not install a %s handler.", name)


def _shutdown(
    worker: ApplianceCaptureWorker,
    thread: threading.Thread,
    output_gate: HardwareOutputGate,
    cycle_seconds: float,
) -> None:
    """Stop the worker, then release the output devices — in that order, and
    never while the worker could still be writing to them.

    Bounded at every step, which is what makes this suitable for a service
    manager that expects a process to exit promptly on SIGTERM:

      * the worker is asked to stop and joined with a bound slightly longer
        than one cycle, so a cycle already in flight can finish;
      * the hardware gate is then closed, which first disables all further
        output and only then waits out at most one in-flight write before
        releasing the devices.

    A join that times out does NOT mean the hardware is closed underneath a
    live writer: the gate disables output before releasing anything, so a
    still-running worker stops touching the panel and the pins at that moment.
    If even one in-flight write does not finish within the gate's own bound,
    the devices are deliberately left open rather than closed from under it,
    and that is logged. The worker is a daemon thread either way, so process
    exit tears the rest down.
    """
    worker.stop()
    thread.join(timeout=cycle_seconds + 10.0)
    worker_alive = thread.is_alive()
    if worker_alive:
        logger.warning(
            "Appliance capture worker did not stop within the join timeout; it is a "
            "daemon thread and will not block process exit. Hardware output is "
            "being disabled before any device is released."
        )

    released = output_gate.close()
    if not released:
        logger.warning(
            "Status hardware was left open at shutdown because a write was still "
            "in flight; output is disabled and process exit will release it."
        )
    logger.info(
        "Appliance stopped after %d completed and %d failed cycle(s).",
        worker.cycles_completed,
        worker.cycles_failed,
    )


if __name__ == "__main__":
    sys.exit(main())
