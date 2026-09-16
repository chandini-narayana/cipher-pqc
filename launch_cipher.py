"""launch_cipher.py — CIPHER presentation launcher (docs/SDD.md's Phase
15 presentation-hardening addendum).

The Python half of `Start CIPHER.bat`'s launch flow:

    Start CIPHER.bat -> launch_cipher.py -> preflight.run_preflight()
        -> subprocess: run_demo.py -> poll GET /api/health
        -> only after HTTP 200: webbrowser.open(...)

`run_demo.py` is started as a REAL subprocess with its stdout/stderr
left connected directly to this console (never captured/suppressed) —
if capture, key generation, or Flask startup fails, the real error
appears immediately, exactly as it would running `python run_demo.py`
by hand. Readiness is decided purely by polling the REST API, never by
scraping subprocess output.

The browser is intentionally decoupled from the server process: closing
the browser tab never stops CIPHER, and stopping CIPHER (Ctrl+C here)
never depends on the browser. Ctrl+C terminates the tracked run_demo.py
subprocess cleanly (SIGTERM, then SIGKILL only if it doesn't exit
within a few seconds) and returns control to the launcher/terminal.

Investigated environment behavior (Phase 15 hardening; confirmed by
direct process-level evidence, not assumed): on Windows, a `venv`'s
`Scripts/python.exe` is CPython's own official "venv launcher" — its
embedded `OriginalFilename` is literally `py.exe`, the Python Software
Foundation's Windows launcher, not a copy of the real interpreter. On
every invocation it reads `pyvenv.cfg`, spawns the actual base
interpreter as a CHILD process to do the real work, and waits for that
child, relaying its exit code. This is standard CPython venv behavior
on Windows for any script at all — reproduced here even for a bare
`print()` with no imports — and has nothing to do with scikit-learn,
joblib, multiprocessing, or Flask's reloader (Flask's reloader was
independently ruled out too: `run_demo.py` runs with `debug=False,
use_reloader=False`, confirmed both by that being the call's explicit
arguments and by Werkzeug's own startup banner always printing "Debug
mode: off"). A `subprocess.Popen([sys.executable, ...])` call made
from inside such a venv therefore always spawns this launcher-then-
worker pair; the launcher process was verified to wait for and relay
its child's exit correctly, so `process.poll()`/`process.wait()` on
the `Popen` handle already track the real lifecycle correctly in this
case. `wait_until_ready()`'s EXIT_GRACE_SECONDS tolerance (below) is
kept regardless, as a small, generic safety margin against a tracked
process appearing to exit slightly before the server is confirmed
healthy for any benign reason — not as a workaround for anything
scikit-learn-specific, which was a wrong diagnosis in an earlier pass
and is not what is happening.

Usage:

    python launch_cipher.py            # preflight, start, open browser
    python launch_cipher.py --check    # preflight only (see preflight.py)
    python launch_cipher.py --no-browser
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Optional

import preflight

PROJECT_ROOT = Path(__file__).resolve().parent
RUN_DEMO_PY = PROJECT_ROOT / "run_demo.py"
APP_URL = f"http://{preflight.DEFAULT_HOST}:{preflight.DEFAULT_PORT}"
HEALTH_URL = f"{APP_URL}/api/health"

READY_TIMEOUT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.25

_BANNER_CHECK_NAMES = ("Web UI", "Demo fixture", "Isolation Forest", "Signing keys", f"Port {preflight.DEFAULT_PORT}")


def _print_header() -> None:
    title = "CIPHER Security Platform"
    print(title)
    print("-" * len(title))
    # One concise, always-useful troubleshooting line: which interpreter
    # is actually running this process. On Windows this is the venv's
    # own launcher path (see module docstring) even when a child process
    # ends up doing the real work under the base interpreter -- exactly
    # what a presenter would want to quote if asked "which Python is
    # this?" No further environment/sys.path detail is dumped here.
    print(f"Python: {sys.executable}")


def _print_preflight_banner(results) -> bool:
    """Prints only the presentation-relevant checks (Web UI, Demo
    fixture, Isolation Forest, Signing keys, Port) in the concise
    "Name: detail" form; "Python runtime"/"Required imports" are
    developer-facing sanity checks, always covered but not shown here.
    Returns False if anything among ALL checks (shown or not) FAILed."""
    by_name = {result.name: result for result in results}
    for name in _BANNER_CHECK_NAMES:
        result = by_name[name]
        print(f"{result.name}: {result.detail}")
    return not preflight.has_blocking_failure(results)


def _terminate(process: subprocess.Popen) -> None:
    """Stop `process`, escalating to a hard kill if it doesn't exit
    promptly. Also absorbs a SECOND KeyboardInterrupt raised by an
    impatient extra Ctrl+C while this cleanup is already in progress —
    that must still result in the child being killed and this function
    returning normally, never an uncaught traceback replacing the
    "CIPHER stopped." message."""
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    except KeyboardInterrupt:
        process.kill()


EXIT_GRACE_SECONDS = 5.0


def wait_until_ready(
    process: subprocess.Popen, timeout_seconds: float = READY_TIMEOUT_SECONDS
) -> Optional[dict]:
    """Polls GET /api/health until it returns 200 (returning the
    parsed JSON body), or `timeout_seconds` elapses (returns None).
    Never reads subprocess stdout/stderr to decide readiness.

    The Popen handle exiting is treated as a strong signal that
    startup failed for real (e.g. a missing/malformed pcap) -- but not
    an instant one: EXIT_GRACE_SECONDS of continued health polling is
    allowed after the process is first observed to have exited before
    giving up, as a small, generic safety margin (a genuine crash still
    fails within a few seconds, never the full timeout). This is not a
    workaround for any specific scikit-learn/joblib behavior -- see the
    module docstring for the investigated, confirmed root cause of the
    Windows venv-launcher process pair, which turned out not to need
    this tolerance at all (it correctly waits for and relays its own
    child). Kept anyway as cheap, harmless general robustness.
    """
    deadline = time.monotonic() + timeout_seconds
    exited_at: Optional[float] = None

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=1) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
            pass

        if process.poll() is not None:
            if exited_at is None:
                exited_at = time.monotonic()
            elif time.monotonic() - exited_at > EXIT_GRACE_SECONDS:
                return None

        time.sleep(POLL_INTERVAL_SECONDS)
    return None


def run(open_browser: bool = True, timeout_seconds: float = READY_TIMEOUT_SECONDS) -> int:
    _print_header()

    results = preflight.run_preflight()
    ok = _print_preflight_banner(results)
    print()

    if not ok:
        print("CIPHER cannot start: one or more required checks failed (see above).")
        print("Run `python preflight.py` for the full check report.")
        return 1

    print("Starting CIPHER...")
    # stdout/stderr are left connected to this console on purpose —
    # see module docstring: a real startup failure must stay visible,
    # never be swallowed by a pipe nobody reads.
    process = subprocess.Popen([sys.executable, str(RUN_DEMO_PY)], cwd=PROJECT_ROOT)

    try:
        health = wait_until_ready(process, timeout_seconds)

        if health is None:
            if process.poll() is not None:
                print(f"\nCIPHER exited before starting (exit code {process.returncode}). See the messages above.")
            else:
                print(f"\nCIPHER did not become ready within {timeout_seconds:.0f}s. Stopping it.")
                _terminate(process)
            return 1

        print(f"Analysis complete: {health['devices_assessed']} devices")
        print(f"Reports generated: {health['reports_generated']}")
        print(f"CIPHER ready at {APP_URL}")
        print()
        print("Evaluation command: python evaluate_demo.py")
        print()
        print("Press Ctrl+C to stop.")

        if open_browser:
            webbrowser.open(APP_URL)

        return process.wait()
    except KeyboardInterrupt:
        print("\nStopping CIPHER...")
        _terminate(process)
        print("CIPHER stopped.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Launch the CIPHER integrated demo application.")
    parser.add_argument(
        "--check", action="store_true", help="Run preflight checks only; do not start CIPHER (see preflight.py)."
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="Do not open a browser automatically once CIPHER is ready."
    )
    args = parser.parse_args()

    if args.check:
        return preflight.main()

    return run(open_browser=not args.no_browser)


if __name__ == "__main__":
    sys.exit(main())
