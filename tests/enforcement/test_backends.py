"""Unit tests for enforcement.backends — IsolationOutcome, IsolationBackend,
and NoOpIsolationBackend (docs/SDD.md Phase 14 addendum).

No real networking/firewall command is ever executed here — only
NoOpIsolationBackend is exercised, and it is defined never to do so.
"""
from __future__ import annotations

import logging

import pytest

from enforcement.backends import IsolationBackend, IsolationOutcome, NoOpIsolationBackend


def test_isolate_returns_requested_true() -> None:
    outcome = NoOpIsolationBackend().isolate("192.168.1.10", 9)
    assert outcome.requested is True


def test_isolate_returns_enforced_false() -> None:
    outcome = NoOpIsolationBackend().isolate("192.168.1.10", 9)
    assert outcome.enforced is False


def test_isolate_reason_clearly_states_hardware_unavailable() -> None:
    outcome = NoOpIsolationBackend().isolate("192.168.1.10", 9)
    assert "unavailable" in outcome.reason.lower()


def test_isolate_preserves_the_device_ip_and_risk_score() -> None:
    outcome = NoOpIsolationBackend().isolate("192.168.1.10", 9)
    assert outcome.device_ip == "192.168.1.10"
    assert outcome.risk_score == 9


def test_isolate_returns_an_isolation_outcome_instance() -> None:
    outcome = NoOpIsolationBackend().isolate("192.168.1.10", 9)
    assert isinstance(outcome, IsolationOutcome)


def test_isolate_logs_a_warning(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="enforcement.backends"):
        NoOpIsolationBackend().isolate("192.168.1.10", 9)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "192.168.1.10" in warnings[0].getMessage()


def test_noop_backend_never_imports_subprocess_or_os_system() -> None:
    """Static confirmation that no process-spawning capability exists
    anywhere in this module — not merely that it wasn't called."""
    import ast
    import inspect

    import enforcement.backends as backends_module

    tree = ast.parse(inspect.getsource(backends_module))
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])

    assert "subprocess" not in imported_modules
    assert "os" not in imported_modules


def test_noop_backend_is_the_only_concrete_backend_in_this_module() -> None:
    """Guards against silently adding a real Linux/iptables backend in
    this phase — Phase 14 is explicitly NoOp-only on Windows."""
    import enforcement.backends as backends_module

    concrete_backends = [
        name
        for name, obj in vars(backends_module).items()
        if isinstance(obj, type)
        and issubclass(obj, IsolationBackend)
        and obj is not IsolationBackend
    ]
    assert concrete_backends == ["NoOpIsolationBackend"]


def test_isolation_backend_is_an_abstract_interface() -> None:
    with pytest.raises(TypeError):
        IsolationBackend()  # abstract - cannot be instantiated directly
