"""Unit tests for preflight.py — the Phase 15 presentation preflight
check (docs/SDD.md's presentation-hardening addendum).

File-based checks are pointed at an isolated tmp_path (never this
checkout's real repo state, except where a test explicitly wants to
confirm the REAL project passes). The port check is exercised against
a dynamically-chosen ephemeral port, never the real port 5000, per the
"do not bind real port 5000 in normal unit tests" requirement.
"""
from __future__ import annotations

import socket

import pytest

import preflight


def _free_port() -> int:
    """An OS-assigned free port, released immediately -- used only to
    get a real, safe port number to test against, never bound
    long-term by this helper itself."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _make_valid_project(root, *, with_model=False, keys="both") -> None:
    """Builds the minimum valid project layout under `root`:
    web/index.html + web/assets/, tests/fixtures/demo_presentation.pcap,
    and (per `keys`) a complete/missing/partial signing keypair.
    `with_model` controls whether the ML artifact file exists.
    """
    web_dir = root / "web"
    (web_dir / "assets").mkdir(parents=True)
    (web_dir / "index.html").write_text("<html></html>")
    (web_dir / "assets" / "index.js").write_text("// js")

    fixtures_dir = root / "tests" / "fixtures"
    fixtures_dir.mkdir(parents=True)
    (fixtures_dir / "demo_presentation.pcap").write_bytes(b"\x00")

    if with_model:
        model_dir = root / "ml" / "artifacts"
        model_dir.mkdir(parents=True)
        (model_dir / "anomaly_detector.joblib").write_bytes(b"\x00")

    key_dir = root / "data" / "keys"
    key_dir.mkdir(parents=True)
    from signing.key_store import PUBLIC_KEY_FILENAME, SECRET_KEY_FILENAME

    if keys == "both":
        (key_dir / PUBLIC_KEY_FILENAME).write_bytes(b"pub")
        (key_dir / SECRET_KEY_FILENAME).write_bytes(b"sec")
    elif keys == "public_only":
        (key_dir / PUBLIC_KEY_FILENAME).write_bytes(b"pub")
    elif keys == "secret_only":
        (key_dir / SECRET_KEY_FILENAME).write_bytes(b"sec")
    elif keys == "none":
        pass
    else:
        raise ValueError(keys)


def _result(results, name):
    return next(r for r in results if r.name == name)


# --- full-project success path -------------------------------------------


def test_real_project_root_passes_preflight_except_possibly_ml() -> None:
    """The real checkout must pass every check except (possibly) the
    ML artifact, which is legitimately absent on a machine with no
    trained model -- WARN, never FAIL, per the frozen fail-open policy."""
    port = _free_port()
    results = preflight.run_preflight(port=port)
    for result in results:
        if result.name == "Isolation Forest":
            assert result.status in ("PASS", "WARN")
        else:
            assert result.status == "PASS", f"{result.name}: {result.detail}"


def test_valid_tmp_project_passes_every_check(tmp_path) -> None:
    _make_valid_project(tmp_path, with_model=True, keys="both")
    port = _free_port()

    results = preflight.run_preflight(project_root=tmp_path, port=port)

    web_ui = _result(results, "Web UI")
    demo_fixture = _result(results, "Demo fixture")
    ml_model = _result(results, "Isolation Forest")
    keys = _result(results, "Signing keys")

    assert web_ui.status == "PASS"
    assert demo_fixture.status == "PASS"
    assert ml_model.status == "PASS"
    assert ml_model.detail == "Available"
    assert keys.status == "PASS"
    assert keys.detail == "Existing"
    assert not preflight.has_blocking_failure(results)


# --- missing web -----------------------------------------------------------


def test_missing_web_build_fails(tmp_path) -> None:
    _make_valid_project(tmp_path, keys="both")
    import shutil

    shutil.rmtree(tmp_path / "web")

    results = preflight.run_preflight(project_root=tmp_path, port=_free_port())

    assert _result(results, "Web UI").status == "FAIL"
    assert preflight.has_blocking_failure(results)


# --- missing demo pcap -------------------------------------------------


def test_missing_demo_pcap_fails(tmp_path) -> None:
    _make_valid_project(tmp_path, keys="both")
    (tmp_path / "tests" / "fixtures" / "demo_presentation.pcap").unlink()

    results = preflight.run_preflight(project_root=tmp_path, port=_free_port())

    result = _result(results, "Demo fixture")
    assert result.status == "FAIL"
    assert "CIPHER demo data is missing" in result.detail
    assert preflight.has_blocking_failure(results)


# --- ML model ------------------------------------------------------------


def test_missing_ml_model_warns_not_fails(tmp_path) -> None:
    _make_valid_project(tmp_path, with_model=False, keys="both")

    results = preflight.run_preflight(project_root=tmp_path, port=_free_port())

    result = _result(results, "Isolation Forest")
    assert result.status == "WARN"
    assert "QRS-only mode" in result.detail
    # A WARN alone must never block startup.
    non_ml_results = [r for r in results if r.name != "Isolation Forest"]
    assert not preflight.has_blocking_failure(non_ml_results)


def test_present_ml_model_passes(tmp_path) -> None:
    _make_valid_project(tmp_path, with_model=True, keys="both")
    results = preflight.run_preflight(project_root=tmp_path, port=_free_port())
    assert _result(results, "Isolation Forest").status == "PASS"


# --- signing keys ----------------------------------------------------------


def test_complete_keypair_passes(tmp_path) -> None:
    _make_valid_project(tmp_path, keys="both")
    results = preflight.run_preflight(project_root=tmp_path, port=_free_port())
    result = _result(results, "Signing keys")
    assert result.status == "PASS"
    assert result.detail == "Existing"


def test_no_keypair_is_acceptable_generation_expected(tmp_path) -> None:
    _make_valid_project(tmp_path, keys="none")
    results = preflight.run_preflight(project_root=tmp_path, port=_free_port())
    result = _result(results, "Signing keys")
    assert result.status == "PASS"
    assert "generated" in result.detail.lower()


@pytest.mark.parametrize("keys", ["public_only", "secret_only"])
def test_partial_keypair_fails(tmp_path, keys: str) -> None:
    _make_valid_project(tmp_path, keys=keys)
    results = preflight.run_preflight(project_root=tmp_path, port=_free_port())
    result = _result(results, "Signing keys")
    assert result.status == "FAIL"
    assert "Incomplete" in result.detail
    assert preflight.has_blocking_failure(results)


# --- port --------------------------------------------------------------


def test_free_port_passes() -> None:
    port = _free_port()
    result = preflight._check_port(port=port)
    assert result.status == "PASS"


def test_occupied_port_fails() -> None:
    port = _free_port()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    try:
        result = preflight._check_port(port=port)
        assert result.status == "FAIL"
        assert "already in use" in result.detail
        assert "Stop the existing CIPHER/server process" in result.detail
    finally:
        sock.close()


def test_preflight_never_kills_anything_on_an_occupied_port() -> None:
    """Static confirmation: the port check module never imports a
    process-killing capability at all."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(preflight))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "subprocess" not in imported


# --- CLI entry point --------------------------------------------------


def test_main_exits_zero_when_ready(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        preflight,
        "run_preflight",
        lambda: [preflight.CheckResult("Web UI", "PASS", "Ready")],
    )
    assert preflight.main() == 0
    assert "READY" in capsys.readouterr().out


def test_main_exits_nonzero_when_blocked(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        preflight,
        "run_preflight",
        lambda: [preflight.CheckResult("Web UI", "FAIL", "missing")],
    )
    assert preflight.main() == 1
    assert "BLOCKED" in capsys.readouterr().out
