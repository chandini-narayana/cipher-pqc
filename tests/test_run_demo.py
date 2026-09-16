"""Unit tests for run_demo.py's composition — the third composition
root that serves the integrated React UI + REST API from one Flask
process (docs/SDD.md's Phase 15 addendum).

Mirrors tests/test_run_api.py's pattern exactly: Flask.run is patched
out so no test ever binds a real port or blocks. WEB_DIR is left
pointing at this repo's real, committed web/ directory throughout
(never monkeypatched to a tmp path in the success-path test) so the
Path(__file__)-based resolution required by docs/SDD.md's Phase 15
addendum is exercised for real, even while cwd is redirected via
monkeypatch.chdir(tmp_path).
"""
from __future__ import annotations

from flask import Flask

import run_demo
from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH
from tests.fixtures.generate_fixtures import main as generate_fixtures


def test_run_demo_reaches_server_startup_without_binding_a_port(tmp_path, monkeypatch) -> None:
    if not SAMPLE_PCAP_PATH.exists():
        generate_fixtures()

    # Isolate every relative default path (LOG_DIR, DATA_DIR,
    # SIGNING_KEY_PATH, report output) inside tmp_path — never touch
    # this checkout's real data/logs/data/keys.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PCAP_PATH", str(SAMPLE_PCAP_PATH))

    captured = {}

    def fake_run(self, host=None, port=None):
        captured["ran"] = True
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr(Flask, "run", fake_run)

    exit_code = run_demo.main()

    assert exit_code == 0
    assert captured["ran"] is True
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 5000


def test_run_demo_defaults_to_the_demo_presentation_fixture_when_pcap_path_unset(
    tmp_path, monkeypatch
) -> None:
    """The Phase 15 evaluation addendum's default-demo-data design:
    with no explicit PCAP_PATH, run_demo.py must use its own
    demo_presentation.pcap (LOW + MEDIUM + HIGH spread), not
    config.constants.DEFAULT_PCAP_PATH's sample.pcap (MEDIUM-only)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PCAP_PATH", raising=False)

    captured = {}

    def fake_run(self, host=None, port=None):
        captured["ran"] = True

    monkeypatch.setattr(Flask, "run", fake_run)

    def fake_create_app(state, settings):
        captured["state"] = state
        return Flask("fake")

    monkeypatch.setattr(run_demo, "create_app", fake_create_app)

    exit_code = run_demo.main()

    assert exit_code == 0
    assert captured["ran"] is True
    from models.enums import RiskCategory

    categories = {a.final_category for a in captured["state"].assessments_by_ip.values()}
    assert RiskCategory.LOW in categories
    assert RiskCategory.MEDIUM in categories
    assert RiskCategory.HIGH in categories


def test_run_demo_respects_an_explicit_pcap_path_override(tmp_path, monkeypatch) -> None:
    """An explicit PCAP_PATH must still win over the demo-fixture
    default — this is an opt-out, not a hardcoded behavior."""
    if not SAMPLE_PCAP_PATH.exists():
        generate_fixtures()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PCAP_PATH", str(SAMPLE_PCAP_PATH))

    captured = {}

    def fake_run(self, host=None, port=None):
        captured["ran"] = True

    monkeypatch.setattr(Flask, "run", fake_run)

    def fake_create_app(state, settings):
        captured["state"] = state
        return Flask("fake")

    monkeypatch.setattr(run_demo, "create_app", fake_create_app)

    exit_code = run_demo.main()

    assert exit_code == 0
    assert captured["state"].devices_assessed == 3  # sample.pcap's 3 devices, not the demo fixture's 5


def test_run_demo_fails_fast_when_presentation_fixture_missing(tmp_path, monkeypatch, capsys) -> None:
    """The committed presentation fixture is a version-controlled
    runtime asset, not something generated at startup: if it's ever
    missing, this must fail immediately with a clear, actionable
    message — never spend ~50-60s regenerating it (which would defeat
    the <30s boot target), and never touch the capture path at all."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("PCAP_PATH", raising=False)
    monkeypatch.setattr(run_demo, "DEFAULT_DEMO_PCAP_PATH", tmp_path / "no_such_presentation.pcap")

    def _forbidden(*args, **kwargs):
        raise AssertionError("get_capture_source must not be called when the presentation fixture is missing")

    monkeypatch.setattr(run_demo, "get_capture_source", _forbidden)

    exit_code = run_demo.main()

    assert exit_code == 1
    assert "CIPHER presentation data is missing" in capsys.readouterr().out


def test_run_demo_never_imports_the_evaluation_fixture_generator() -> None:
    """Static confirmation, not just behavioral: run_demo.py's own
    source must never import tests.fixtures.generate_evaluation_fixtures
    — runtime fixture use and test/dev-time fixture generation are
    deliberately kept as two separate concerns (docs/SDD.md's Phase 15
    evaluation addendum). This guards against a future edit silently
    reintroducing the ~50-60s startup-time generation path."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(run_demo))
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)

    assert "tests.fixtures.generate_evaluation_fixtures" not in imported_modules


def test_run_demo_mock_mode_does_not_start_a_server(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)  # configure_logging() still runs before the early return
    monkeypatch.setenv("CAPTURE_MODE", "mock")

    def _forbidden(*args, **kwargs):
        raise AssertionError("create_app must not be called for capture_mode=mock")

    monkeypatch.setattr(run_demo, "create_app", _forbidden)

    assert run_demo.main() == 0


def test_run_demo_fails_fast_when_web_build_missing(tmp_path, monkeypatch, capsys) -> None:
    """A missing web/ build must be caught before any capture work
    starts — get_capture_source must never even be called."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_demo, "WEB_DIR", tmp_path / "no_such_web_dir")

    def _forbidden(*args, **kwargs):
        raise AssertionError("get_capture_source must not be called when the web build is missing")

    monkeypatch.setattr(run_demo, "get_capture_source", _forbidden)

    exit_code = run_demo.main()

    assert exit_code == 1
    assert "CIPHER web application is missing" in capsys.readouterr().out
