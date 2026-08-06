"""End-to-end smoke test for main.py as it stands at the end of Step 3:
must run to completion, exit 0, and show real (not faked) startup
behavior — configuration loaded, logging initialized, banner printed,
graceful exit explained.
"""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_main_exits_zero_with_expected_output() -> None:
    result = subprocess.run(
        [sys.executable, "main.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "CIPHER" in result.stdout
    assert "Capture mode" in result.stdout
    assert "exiting gracefully" in result.stdout.lower()


def test_main_respects_env_override(monkeypatch) -> None:
    import os

    env = os.environ.copy()
    env["CAPTURE_MODE"] = "mock"
    result = subprocess.run(
        [sys.executable, "main.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    assert result.returncode == 0
    assert "mock" in result.stdout
