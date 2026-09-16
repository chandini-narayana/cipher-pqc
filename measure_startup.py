"""measure_startup.py — measures python run_demo.py's real startup
time against the Execution Report's <30s target (docs/SDD.md's Phase
15 evaluation addendum).

Launches run_demo.py as a real subprocess on a non-default port (so it
never collides with a demo a user already has running on 127.0.0.1:5000),
polls GET /api/health until it returns HTTP 200, and reports the
elapsed wall-clock time via time.perf_counter(). The subprocess's cwd
is a fresh temporary directory — never this checkout's real
data/logs/data/keys — and PCAP_PATH is pointed at the real committed
tests/fixtures/sample.pcap via an absolute path (run_demo.py's own
WEB_DIR is resolved from its file location, not cwd, so this doesn't
affect which committed web/ build it serves). The subprocess is always
terminated before this script exits, even on timeout or error — this
never leaves a background server running.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent
RUN_DEMO_PY = REPO_ROOT / "run_demo.py"
SAMPLE_PCAP = REPO_ROOT / "tests" / "fixtures" / "sample.pcap"

DEFAULT_PORT = 5099
DEFAULT_TIMEOUT_SECONDS = 30.0
POLL_INTERVAL_SECONDS = 0.1
STARTUP_TARGET_SECONDS = 30.0


def measure_startup(
    port: int = DEFAULT_PORT,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> float:
    """Return the elapsed seconds from subprocess launch until
    GET /api/health first returns 200 OK.

    Raises:
        RuntimeError: if the subprocess exits before ever answering.
        TimeoutError: if it never answers within `timeout_seconds`.
    """
    with tempfile.TemporaryDirectory(prefix="cipher-startup-measurement-") as tmp_dir:
        env = os.environ.copy()
        env["PCAP_PATH"] = str(SAMPLE_PCAP)
        env["FLASK_PORT"] = str(port)

        start = time.perf_counter()
        process = subprocess.Popen(
            [sys.executable, str(RUN_DEMO_PY)],
            cwd=tmp_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            health_url = f"http://127.0.0.1:{port}/api/health"
            deadline = start + timeout_seconds
            while time.perf_counter() < deadline:
                if process.poll() is not None:
                    output = process.stdout.read() if process.stdout else ""
                    raise RuntimeError(
                        f"run_demo.py exited early (code {process.returncode}) "
                        f"before answering {health_url}:\n{output}"
                    )
                try:
                    with urllib.request.urlopen(health_url, timeout=1) as response:
                        if response.status == 200:
                            return time.perf_counter() - start
                except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                    pass
                time.sleep(POLL_INTERVAL_SECONDS)
            raise TimeoutError(
                f"run_demo.py did not respond at {health_url} within {timeout_seconds}s"
            )
        finally:
            _terminate(process)


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    print("Measuring python run_demo.py startup time...")
    try:
        seconds = measure_startup()
    except (RuntimeError, TimeoutError) as exc:
        print(f"FAILED: {exc}")
        return 1

    passed = seconds < STARTUP_TARGET_SECONDS
    print(f"startup_seconds = {seconds:.3f}")
    print(
        f"Execution Report target: < {STARTUP_TARGET_SECONDS:.0f}s -> "
        f"{'PASS' if passed else 'FAIL'}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
