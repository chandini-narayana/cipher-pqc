"""Static dependency checks: dashboard/ must never import capture,
fingerprint, risk scoring, ml classifier, fusion, or signing
internals, must not recompute an assessment, and no database or
frontend implementation is introduced by Phase 12."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import dashboard.app as app_module
import dashboard.routes as routes_module
import dashboard.serializers as serializers_module
import dashboard.state as state_module

_MODULES = (app_module, routes_module, serializers_module, state_module)

_FORBIDDEN = {"capture", "fingerprint", "risk", "ml", "fusion", "pipeline", "signing"}
_DATABASE_MODULES = {"sqlite3", "sqlalchemy", "psycopg2", "pymongo"}


def _imported_top_level_modules(module) -> set:
    tree = ast.parse(inspect.getsource(module))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def test_dashboard_modules_do_not_import_forbidden_packages() -> None:
    for module in _MODULES:
        found = _imported_top_level_modules(module) & _FORBIDDEN
        assert not found, f"{module.__name__} imports forbidden package(s): {found}"


def test_no_database_dependency_introduced() -> None:
    for module in _MODULES:
        found = _imported_top_level_modules(module) & _DATABASE_MODULES
        assert not found, f"{module.__name__} imports a database package: {found}"


def test_no_frontend_implementation_was_introduced() -> None:
    """Phase 12 is backend-only — no frontend/ directory should exist
    anywhere in this repository."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    assert not (repo_root / "frontend").exists()
