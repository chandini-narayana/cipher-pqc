"""Shared fixtures for dashboard/ REST API tests.

Builds one real ApplicationState + Flask app per test using real
signing keys and one real generated PDF (Phase 10's generate_report)
— no HTTP server is ever started; Flask's own test_client() drives
every request in-process.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from config.settings import Settings
from dashboard import build_application_state, create_app
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment
from reports.pdf_generator import generate_report
from signing import generate_keypair

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

HIGH_IP = "192.168.1.10"
LOW_IP = "192.168.1.5"


def _high_assessment() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact(HIGH_IP, TS),
        risk_assessment=RiskAssessment(
            9, RiskCategory.HIGH, "Upgrade from TLS 1.0 to TLS 1.3.", "NIST SP 800-52r2"
        ),
        anomaly_assessment=AnomalyAssessment(anomaly_score=0.8, is_anomaly=True, confidence=0.9),
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )


def _low_assessment() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact(LOW_IP, TS),
        risk_assessment=RiskAssessment(1, RiskCategory.LOW, "No remediation needed.", "N/A"),
        anomaly_assessment=None,
        final_category=RiskCategory.LOW,
        assessed_at=TS,
    )


@pytest.fixture(scope="session")
def _keypair():
    return generate_keypair()


@pytest.fixture()
def seeded_state(tmp_path, _keypair):
    """(ApplicationState, pdf_path, ReportMetadata) for one HIGH device
    with a real generated report, and one LOW device with none."""
    public_key, secret_key = _keypair
    high = _high_assessment()
    low = _low_assessment()

    path, metadata = generate_report(high, secret_key, public_key, output_dir=tmp_path)

    state = build_application_state([high, low], [(path, metadata)])
    return state, path, metadata


@pytest.fixture()
def app(seeded_state):
    state, _path, _metadata = seeded_state
    return create_app(state, Settings())


@pytest.fixture()
def app_with_cors(seeded_state):
    state, _path, _metadata = seeded_state
    return create_app(state, Settings(cors_origin="http://localhost:3000"))


@pytest.fixture()
def client(app):
    return app.test_client()
