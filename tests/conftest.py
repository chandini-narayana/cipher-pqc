"""Shared pytest configuration for the CIPHER test suite.

Ensures tests/fixtures/sample.pcap and the Phase 15 evaluation fixtures
exist before any test needs them, generating each via its own
generate_*.py script on first use if missing — so `pytest` works out
of the box after a fresh clone, with no separate manual
fixture-generation step. This is TEST-side generation only; it has no
bearing on run_demo.py, which uses its own committed presentation
fixture directly and never imports or calls this generation logic (see
docs/SDD.md's Phase 15 evaluation addendum). Every evaluation pcap
except demo_presentation.pcap is gitignored (tests/fixtures/*.pcap)
and regenerated deterministically rather than committed as an opaque
binary; demo_presentation.pcap is the one committed exception (a
`!tests/fixtures/demo_presentation.pcap` negation in .gitignore) so a
fresh clone always has it without needing this fixture to run first —
this autouse fixture is then just a safety net if it's ever deleted.
"""
from __future__ import annotations

import pytest

from tests.fixtures.generate_evaluation_fixtures import (
    DEMO_PRESENTATION_PCAP,
    ENCRYPTED_ENTROPY_PCAP,
    HIGH_RISK_PCAP,
    KNOWN_SAFE_SET_PCAP,
    LEGACY_TLS10_PCAP,
    MQTT_PCAP,
    PLAIN_HTTP_PCAP,
    SECURE_TLS13_PCAP,
    WEAK_RSA_PCAP,
)
from tests.fixtures.generate_evaluation_fixtures import main as generate_evaluation_fixtures
from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH, main as generate_fixtures

_EVALUATION_FIXTURE_PATHS = (
    SECURE_TLS13_PCAP,
    LEGACY_TLS10_PCAP,
    WEAK_RSA_PCAP,
    PLAIN_HTTP_PCAP,
    HIGH_RISK_PCAP,
    MQTT_PCAP,
    KNOWN_SAFE_SET_PCAP,
    ENCRYPTED_ENTROPY_PCAP,
    DEMO_PRESENTATION_PCAP,
)


@pytest.fixture(scope="session", autouse=True)
def _ensure_sample_pcap_exists() -> None:
    if not SAMPLE_PCAP_PATH.exists():
        generate_fixtures()


@pytest.fixture(scope="session", autouse=True)
def _ensure_evaluation_fixtures_exist() -> None:
    if not all(path.exists() for path in _EVALUATION_FIXTURE_PATHS):
        generate_evaluation_fixtures()