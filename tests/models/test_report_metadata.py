"""Unit tests for models.report_metadata.ReportMetadata."""
from datetime import datetime

import pytest

from models.report_metadata import ReportMetadata

TS = datetime(2026, 1, 1, 12, 0, 0)


def _valid_kwargs(**overrides):
    kwargs = dict(
        report_id="rpt-0001",
        device_ip="192.168.1.10",
        generated_at=TS,
        page_count=3,
        report_hash="abc123",
        signature_hex="deadbeef",
        signing_algorithm="ML-DSA-44 (FIPS 204; derived from CRYSTALS-Dilithium)",
        verification_status=True,
    )
    kwargs.update(overrides)
    return kwargs


def test_valid_report_metadata() -> None:
    rm = ReportMetadata(**_valid_kwargs())
    assert rm.page_count == 3


def test_rejects_empty_report_id() -> None:
    with pytest.raises(ValueError, match="report_id"):
        ReportMetadata(**_valid_kwargs(report_id=""))


def test_rejects_invalid_device_ip() -> None:
    with pytest.raises(ValueError, match="valid IP"):
        ReportMetadata(**_valid_kwargs(device_ip="bad-ip"))


@pytest.mark.parametrize("page_count", [0, 4, 10])
def test_rejects_page_count_outside_frozen_three_page_limit(page_count: int) -> None:
    """Enforces the frozen report architecture: max 3 pages."""
    with pytest.raises(ValueError, match="page_count"):
        ReportMetadata(**_valid_kwargs(page_count=page_count))


def test_accepts_boundary_page_counts() -> None:
    assert ReportMetadata(**_valid_kwargs(page_count=1)).page_count == 1
    assert ReportMetadata(**_valid_kwargs(page_count=3)).page_count == 3


def test_rejects_invalid_report_hash() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        ReportMetadata(**_valid_kwargs(report_hash="not-hex!"))


def test_rejects_invalid_signature_hex() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        ReportMetadata(**_valid_kwargs(signature_hex="zz"))


def test_rejects_empty_signing_algorithm() -> None:
    with pytest.raises(ValueError, match="signing_algorithm"):
        ReportMetadata(**_valid_kwargs(signing_algorithm=""))


def test_round_trip_serialization() -> None:
    rm1 = ReportMetadata(**_valid_kwargs())
    rm2 = ReportMetadata.from_dict(rm1.to_dict())
    assert rm1 == rm2