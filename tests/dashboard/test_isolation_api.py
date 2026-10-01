"""Phase 3B tests for isolation state in the REST contract
(docs/SDD.md Phase 3B addendum).

Exercises dashboard.serializers directly for the shape, and the live
Flask test client for the seeded devices, so both the DTO and the wired
endpoints are covered. The existing exact-shape assertions in
tests/dashboard/test_devices.py remain the guard on the overall key set.
"""
from __future__ import annotations

from datetime import datetime, timezone

from dashboard.serializers import serialize_device_detail, serialize_device_summary
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import (
    ENFORCED,
    FAILED,
    NOT_REQUESTED,
    REQUESTED_NOT_ENFORCED,
    IsolationStatus,
)
from models.risk_assessment import RiskAssessment
from tests.dashboard.conftest import HIGH_IP, LOW_IP

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

_ISOLATION_KEYS = {
    "requested",
    "enforced",
    "backend",
    "reason",
    "requested_at",
    "enforcement_capable",
    "status",
}


def _assessment(isolation: IsolationStatus | None) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact("10.0.0.5", TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


def _status(**overrides) -> IsolationStatus:
    kwargs = {
        "requested": True,
        "enforced": False,
        "backend": "noop",
        "reason": "Hardware enforcement unavailable in current deployment",
        "requested_at": TS,
        "enforcement_capable": False,
    }
    kwargs.update(overrides)
    return IsolationStatus(**kwargs)


# --- shape ---


def test_summary_always_includes_an_isolation_object() -> None:
    """Always present, so a client never has to branch on a missing key."""
    summary = serialize_device_summary(_assessment(None), has_report=False)
    assert set(summary["isolation"].keys()) == _ISOLATION_KEYS


def test_detail_includes_the_same_isolation_object() -> None:
    detail = serialize_device_detail(_assessment(_status()), has_report=True)
    assert set(detail["isolation"].keys()) == _ISOLATION_KEYS


def test_detail_still_carries_its_existing_fields() -> None:
    """Backward compatibility: nothing was displaced by the addition."""
    detail = serialize_device_detail(_assessment(_status()), has_report=True)
    assert detail["device_ip"] == "10.0.0.5"
    assert detail["risk_score"] == 9
    assert detail["remediation"] == "Upgrade TLS."
    assert detail["nist_reference"] == "NIST SP 800-52r2"
    assert detail["has_report"] is True


# --- the four states ---


def test_absent_isolation_serializes_as_not_requested() -> None:
    isolation = serialize_device_summary(_assessment(None), has_report=False)["isolation"]
    assert isolation["requested"] is False
    assert isolation["enforced"] is False
    assert isolation["backend"] is None
    assert isolation["reason"] is None
    assert isolation["requested_at"] is None
    assert isolation["status"] == NOT_REQUESTED


def test_noop_isolation_serializes_as_requested_not_enforced() -> None:
    isolation = serialize_device_summary(_assessment(_status()), has_report=False)["isolation"]
    assert isolation["requested"] is True
    assert isolation["enforced"] is False
    assert isolation["backend"] == "noop"
    assert isolation["enforcement_capable"] is False
    assert isolation["status"] == REQUESTED_NOT_ENFORCED


def test_successful_enforcement_serializes_as_enforced() -> None:
    status = _status(enforced=True, backend="linux", enforcement_capable=True, reason="enforced")
    isolation = serialize_device_summary(_assessment(status), has_report=False)["isolation"]
    assert isolation["enforced"] is True
    assert isolation["backend"] == "linux"
    assert isolation["status"] == ENFORCED


def test_failed_enforcement_serializes_as_failed() -> None:
    status = _status(backend="linux", enforcement_capable=True, reason="permission denied")
    isolation = serialize_device_summary(_assessment(status), has_report=False)["isolation"]
    assert isolation["enforced"] is False
    assert isolation["status"] == FAILED
    assert isolation["reason"] == "permission denied"


def test_requested_at_is_serialized_as_an_iso_timestamp() -> None:
    isolation = serialize_device_summary(_assessment(_status()), has_report=False)["isolation"]
    assert isolation["requested_at"] == TS.isoformat()


def test_a_noop_response_never_claims_enforcement() -> None:
    """The anti-overclaim rule, at the API boundary."""
    isolation = serialize_device_summary(_assessment(_status()), has_report=False)["isolation"]
    assert isolation["enforced"] is False
    assert isolation["status"] != ENFORCED


# --- wired endpoints ---


def test_devices_list_exposes_isolation_for_every_device(client) -> None:
    devices = client.get("/api/devices").get_json()["devices"]
    for device in devices:
        assert set(device["isolation"].keys()) == _ISOLATION_KEYS


def test_seeded_devices_report_not_requested(client) -> None:
    """The existing fixtures carry no isolation state, which must surface
    as "Not requested" rather than as an error or a missing key."""
    for ip in (HIGH_IP, LOW_IP):
        isolation = client.get(f"/api/devices/{ip}").get_json()["isolation"]
        assert isolation["status"] == NOT_REQUESTED
        assert isolation["requested"] is False


def test_unknown_device_still_404s(client) -> None:
    """Error behavior is untouched by the addition."""
    assert client.get("/api/devices/203.0.113.9").status_code == 404


def test_health_endpoint_is_unchanged(client) -> None:
    data = client.get("/api/health").get_json()
    assert data["status"] == "ok"
    assert "isolation" not in data


def test_serializers_module_does_not_import_enforcement() -> None:
    """dashboard/ reads an already-decided result; it never reaches into
    the enforcement layer to derive one."""
    import ast
    import inspect

    import dashboard.serializers as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "enforcement" not in imported
