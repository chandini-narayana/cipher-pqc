"""End-to-end smoke test for main.py's Phase 11 offline composition
root: must run to completion, exit 0, and show real (not faked)
startup and capture-processing behavior — configuration loaded,
logging initialized, banner printed, one offline capture pass
completed.

Runs the subprocess with cwd=tmp_path so every relative default path
(LOG_DIR, DATA_DIR, SIGNING_KEY_PATH, and run_capture's report output
directory) resolves inside an isolated temp directory — this test
never touches this checkout's real data/, logs/, or data/keys/.
PCAP_PATH is overridden to an absolute path so the real committed
fixture is still found regardless of cwd.
"""
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MAIN_PY = REPO_ROOT / "main.py"
SAMPLE_PCAP = REPO_ROOT / "tests" / "fixtures" / "sample.pcap"


def test_main_exits_zero_with_expected_output(tmp_path) -> None:
    env = os.environ.copy()
    env["PCAP_PATH"] = str(SAMPLE_PCAP)

    result = subprocess.run(
        [sys.executable, str(MAIN_PY)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0
    assert "CIPHER" in result.stdout
    assert "Capture mode" in result.stdout
    assert "Capture run complete" in result.stdout


def test_main_respects_env_override(tmp_path) -> None:
    env = os.environ.copy()
    env["CAPTURE_MODE"] = "mock"

    result = subprocess.run(
        [sys.executable, str(MAIN_PY)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0
    assert "mock" in result.stdout
