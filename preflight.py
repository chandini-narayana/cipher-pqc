"""preflight.py — CIPHER presentation preflight check (docs/SDD.md's
Phase 15 presentation-hardening addendum).

Validates every runtime asset and precondition `run_demo.py` needs
*before* spending time on a real capture/key/report run — so a
presenter can run this 5 minutes before going on stage and know
exactly what, if anything, needs fixing.

Never starts the application, never regenerates any committed fixture,
never trains an ML model, never deletes or overwrites signing keys,
and never kills another process to free a port. Every check here
mirrors CIPHER's own real, already-approved runtime behavior (fail-
open ML loading, fail-loud on a partial signing keypair, etc.) — it
never invents new policy.

Run directly:

    python preflight.py

Exit code: 0 if CIPHER can start (WARNs are non-blocking), non-zero if
any check FAILs.
"""
from __future__ import annotations

import importlib
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_PORT = 5000
DEFAULT_HOST = "127.0.0.1"


@dataclass(frozen=True)
class CheckResult:
    """One preflight check's outcome. `status` is exactly one of
    "PASS", "WARN", "FAIL". `detail` is a short, human-readable
    explanation — the actual reason, never a placeholder."""

    name: str
    status: str
    detail: str


def _resolve(project_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else project_root / path


def _check_python_runtime() -> CheckResult:
    return CheckResult("Python runtime", "PASS", f"Python {sys.version.split()[0]}")


def _check_required_imports() -> CheckResult:
    """Importing run_demo transitively imports every module (and every
    third-party dependency: flask, scapy, cryptography, dilithium_py,
    reportlab, scikit-learn, joblib) the real application needs — the
    same import graph a real run would exercise, not a hand-picked
    subset that could drift from it."""
    try:
        importlib.import_module("run_demo")
    except Exception as exc:  # noqa: BLE001 - report exactly what failed to import
        return CheckResult("Required imports", "FAIL", f"Failed to import run_demo: {exc!r}")
    return CheckResult("Required imports", "PASS", "All required modules import cleanly")


def _check_web_ui(project_root: Path) -> CheckResult:
    from dashboard.spa import MissingWebBuildError, validate_web_build

    web_dir = project_root / "web"
    try:
        validate_web_build(web_dir)
    except MissingWebBuildError as exc:
        return CheckResult("Web UI", "FAIL", str(exc))
    return CheckResult("Web UI", "PASS", "Ready")


def _check_demo_fixture(project_root: Path) -> CheckResult:
    pcap_path = project_root / "tests" / "fixtures" / "demo_presentation.pcap"
    if pcap_path.is_file():
        return CheckResult("Demo fixture", "PASS", "Ready")
    return CheckResult(
        "Demo fixture",
        "FAIL",
        f"CIPHER demo data is missing.\nExpected: {pcap_path}\n"
        "This file is a committed runtime asset, not something generated "
        "at startup -- restore it from version control (e.g. "
        "`git checkout -- tests/fixtures/demo_presentation.pcap`) rather "
        "than regenerating it here.",
    )


def _check_ml_model(project_root: Path) -> CheckResult:
    """Mirrors ml.loading.load_anomaly_detector's real fail-open
    behavior exactly: a missing model is never fatal, QRS scoring is
    entirely unaffected -- this check reports that accurately as WARN,
    never FAIL, and never trains a model to "fix" it."""
    from config.settings import load_settings

    settings = load_settings()
    model_path = _resolve(project_root, settings.model_path)
    if model_path.is_file():
        return CheckResult("Isolation Forest", "PASS", "Available")
    return CheckResult(
        "Isolation Forest",
        "WARN",
        "Unavailable -- QRS-only mode (anomaly detection will not run; "
        "deterministic QRS risk scoring is unaffected)",
    )


def _check_signing_keys(project_root: Path) -> CheckResult:
    """Preserves the exact approved lifecycle
    (signing.key_store.load_or_create_keypair): both exist -> reuse,
    neither exists -> generate on startup, exactly one exists -> fail.
    Never deletes or regenerates a key file itself."""
    from config.settings import load_settings
    from signing.key_store import PUBLIC_KEY_FILENAME, SECRET_KEY_FILENAME

    settings = load_settings()
    key_dir = _resolve(project_root, settings.signing_key_path)
    public_path = key_dir / PUBLIC_KEY_FILENAME
    secret_path = key_dir / SECRET_KEY_FILENAME
    public_exists = public_path.is_file()
    secret_exists = secret_path.is_file()

    if public_exists and secret_exists:
        return CheckResult("Signing keys", "PASS", "Existing")
    if not public_exists and not secret_exists:
        return CheckResult("Signing keys", "PASS", "Will be generated on startup")

    existing_name = PUBLIC_KEY_FILENAME if public_exists else SECRET_KEY_FILENAME
    missing_name = SECRET_KEY_FILENAME if public_exists else PUBLIC_KEY_FILENAME
    return CheckResult(
        "Signing keys",
        "FAIL",
        f"Incomplete ML-DSA-44 keypair in {key_dir}: found {existing_name} "
        f"but not {missing_name}. CIPHER will refuse to start rather than "
        "regenerate or overwrite the surviving key -- resolve this "
        "manually (restore the missing file, or remove both and let "
        "CIPHER generate a fresh pair) before trying again.",
    )


def _check_port(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> CheckResult:
    """Never kills whatever is holding the port -- just reports it
    clearly so the presenter can stop it themselves."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.bind((host, port))
    except OSError:
        return CheckResult(
            f"Port {port}",
            "FAIL",
            f"Port {port} is already in use.\n"
            "Stop the existing CIPHER/server process and try again.",
        )
    finally:
        sock.close()
    return CheckResult(f"Port {port}", "PASS", "Available")


def run_preflight(
    project_root: Optional[Path] = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> List[CheckResult]:
    """Run every check and return the full list, in presentation
    order. `project_root`/`host`/`port` are overridable so tests can
    point every file-based check at an isolated tmp_path and every
    network check at a safe, non-default port instead of touching the
    real checkout or the real port 5000."""
    root = project_root if project_root is not None else PROJECT_ROOT
    return [
        _check_python_runtime(),
        _check_required_imports(),
        _check_web_ui(root),
        _check_demo_fixture(root),
        _check_ml_model(root),
        _check_signing_keys(root),
        _check_port(host, port),
    ]


def has_blocking_failure(results: List[CheckResult]) -> bool:
    return any(result.status == "FAIL" for result in results)


def main() -> int:
    results = run_preflight()

    title = "CIPHER Preflight Check"
    print(title)
    print("-" * len(title))
    for result in results:
        print(f"[{result.status}] {result.name}: {result.detail}")
    print()

    if has_blocking_failure(results):
        print("BLOCKED: one or more required checks failed. Fix the issues above before starting CIPHER.")
        return 1

    print("READY: CIPHER can start.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
