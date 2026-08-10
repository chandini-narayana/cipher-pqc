"""Supplementary end-to-end test for main.py as of Step 5.

tests/test_main_step3.py is left untouched — its assertions (banner
present, "Capture mode" shown, exits gracefully) still hold and still
pass. This file adds the one new thing worth checking now: main.py's
message must no longer claim "no capture source is implemented,"
since capture/ is real as of this step.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_main_no_longer_claims_capture_is_unimplemented() -> None:
    result = subprocess.run(
        [sys.executable, "main.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "no capture source is implemented" not in result.stdout.lower()
    assert "pipeline" in result.stdout.lower()


def test_main_still_exits_gracefully_with_zero() -> None:
    """main.py has nothing to actually drive capture through yet
    (pipeline/ doesn't exist), so it must still exit cleanly rather
    than attempting ad-hoc orchestration of its own."""
    result = subprocess.run(
        [sys.executable, "main.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0