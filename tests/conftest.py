"""Shared pytest configuration for the CIPHER test suite.

Ensures tests/fixtures/sample.pcap exists before any test needs it,
generating it via tests/fixtures/generate_fixtures.py on first use if
missing — so `pytest` works out of the box after a fresh clone, with
no separate manual fixture-generation step.
"""
from __future__ import annotations

import pytest

from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH, main as generate_fixtures


@pytest.fixture(scope="session", autouse=True)
def _ensure_sample_pcap_exists() -> None:
    if not SAMPLE_PCAP_PATH.exists():
        generate_fixtures()