"""Scaffold-level smoke tests (Step 2).

These are intentionally shallow: at this stage there is no business logic
to test, only structure. What they verify:
1. Every package under cipher/ imports without raising.
2. `python main.py` runs to completion and exits 0.

As each module gains real implementation in later steps, these smoke
tests stay in place alongside the module's own real unit tests — they
are cheap insurance that the overall project never silently breaks.
"""
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

PACKAGES = [
    "models",
    "capture",
    "entropy",
    "fingerprint",
    "risk",
    "ml",
    "pipeline",
    "dashboard",
    "signing",
    "reports",
    "config",
    "utils",
]

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("package_name", PACKAGES)
def test_package_imports_cleanly(package_name: str) -> None:
    """Every top-level package should import with no exceptions, even
    before it contains real implementation."""
    module = importlib.import_module(package_name)
    assert module is not None


def test_main_runs_and_exits_zero() -> None:
    """python main.py must always execute successfully (project rule 3)."""
    result = subprocess.run(
        [sys.executable, "main.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert "CIPHER" in result.stdout
