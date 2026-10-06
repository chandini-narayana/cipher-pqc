"""Phase A1 end-to-end: a worker publishing cycles while the REAL Flask app
serves the REAL REST contract.

This is the test that proves appliance mode actually works: a genuine
`create_app` + `test_client`, driven by a genuine `ApplianceCaptureWorker`,
with only the capture source and `run_capture` faked. No socket is bound, no
interface is opened, and no hardware is touched.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import pytest

from appliance.worker import ApplianceCaptureWorker
from config.settings import Settings
from dashboard import create_app
from dashboard.state_store import ApplicationStateStore
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.report_metadata import ReportMetadata
from models.risk_assessment import RiskAssessment
from utils.exceptions import CaptureError

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _assessment(
    ip: str,
    risk_score: int = 9,
    category: RiskCategory = RiskCategory.HIGH,
    isolation: Optional[IsolationStatus] = None,
) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(risk_score, category, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=None,
        final_category=category,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


def _report(ip: str, report_id: str = "CIPHER-x"):
    return (
        Path(f"/fake/{report_id}.pdf"),
        ReportMetadata(report_id, ip, TS, 3, "ab" * 32, "cd" * 32, "Dilithium2", "Verified"),
    )


@pytest.fixture
def appliance():
    """A real app over a real store, plus a worker whose cycles are scripted."""
    store = ApplicationStateStore()
    app = create_app(store, Settings())
    results: List[tuple] = []

    def _source_factory():
        return object()

    def _run_capture(capture_source, **kwargs):
        if not results:
            return ([], [])
        return results.pop(0)

    worker = ApplianceCaptureWorker(
        store=store, source_factory=_source_factory, run_capture_fn=_run_capture
    )
    return {
        "store": store,
        "client": app.test_client(),
        "worker": worker,
        "results": results,
    }


# --- the dashboard is reachable before the first cycle -------------------


def test_the_api_serves_an_empty_inventory_immediately(appliance) -> None:
    response = appliance["client"].get("/api/devices")

    assert response.status_code == 200
    assert response.get_json() == {"devices": []}


def test_health_reports_zero_before_the_first_cycle(appliance) -> None:
    data = appliance["client"].get("/api/health").get_json()

    assert data["status"] == "ok"
    assert data["devices_assessed"] == 0
    assert data["reports_generated"] == 0


def test_an_unknown_device_still_404s_before_any_cycle(appliance) -> None:
    assert appliance["client"].get("/api/devices/10.0.0.5").status_code == 404


# --- a cycle becomes visible through the existing endpoints --------------


def test_a_cycles_devices_appear_in_the_device_list(appliance) -> None:
    appliance["results"].append(([_assessment("10.0.0.5")], []))

    appliance["worker"].run_cycle()

    devices = appliance["client"].get("/api/devices").get_json()["devices"]
    assert [d["device_ip"] for d in devices] == ["10.0.0.5"]


def test_the_same_client_sees_new_state_without_a_restart(appliance) -> None:
    """The decisive property: no app rebuild, no reconnect — the next
    request simply sees the newer snapshot."""
    client = appliance["client"]
    assert client.get("/api/devices").get_json()["devices"] == []

    appliance["results"].append(([_assessment("10.0.0.5")], []))
    appliance["worker"].run_cycle()

    assert len(client.get("/api/devices").get_json()["devices"]) == 1


def test_health_counts_follow_the_published_state(appliance) -> None:
    appliance["results"].append(([_assessment("10.0.0.5")], [_report("10.0.0.5")]))

    appliance["worker"].run_cycle()

    data = appliance["client"].get("/api/health").get_json()
    assert data["devices_assessed"] == 1
    assert data["reports_generated"] == 1


def test_device_detail_serves_a_newly_assessed_device(appliance) -> None:
    appliance["results"].append(([_assessment("10.0.0.5")], []))
    appliance["worker"].run_cycle()

    detail = appliance["client"].get("/api/devices/10.0.0.5").get_json()

    assert detail["device_ip"] == "10.0.0.5"
    assert detail["risk_score"] == 9
    assert detail["remediation"] == "Upgrade TLS."


def test_successive_cycles_accumulate_in_the_api(appliance) -> None:
    appliance["results"].extend(
        [
            ([_assessment("10.0.0.5")], []),
            ([_assessment("10.0.0.6")], []),
            ([], []),
        ]
    )

    for _ in range(3):
        appliance["worker"].run_cycle()

    devices = appliance["client"].get("/api/devices").get_json()["devices"]
    assert {d["device_ip"] for d in devices} == {"10.0.0.5", "10.0.0.6"}


def test_a_reassessed_device_is_updated_not_duplicated_in_the_api(appliance) -> None:
    appliance["results"].extend(
        [
            ([_assessment("10.0.0.5", 3, RiskCategory.MEDIUM)], []),
            ([_assessment("10.0.0.5", 9, RiskCategory.HIGH)], []),
        ]
    )

    appliance["worker"].run_cycle()
    appliance["worker"].run_cycle()

    devices = appliance["client"].get("/api/devices").get_json()["devices"]
    assert len(devices) == 1
    assert devices[0]["risk_score"] == 9
    assert devices[0]["final_category"] == "HIGH"


# --- isolation state through the API ------------------------------------


def test_isolation_state_is_visible_through_the_api(appliance) -> None:
    isolation = IsolationStatus(
        requested=True,
        enforced=True,
        backend="linux-iptables",
        reason="Isolated 10.0.0.5 with iptables",
        requested_at=TS,
        enforcement_capable=True,
    )
    appliance["results"].append(([_assessment("10.0.0.5", isolation=isolation)], []))

    appliance["worker"].run_cycle()

    detail = appliance["client"].get("/api/devices/10.0.0.5").get_json()
    assert detail["isolation"]["requested"] is True
    assert detail["isolation"]["enforced"] is True
    assert detail["isolation"]["backend"] == "linux-iptables"
    assert detail["isolation"]["status"] == "Enforced"


def test_a_noop_isolation_outcome_is_not_shown_as_enforced(appliance) -> None:
    """The anti-overclaim rule survives the appliance path."""
    noop = IsolationStatus(True, False, "noop", "unavailable", TS, False)
    appliance["results"].append(([_assessment("10.0.0.5", isolation=noop)], []))

    appliance["worker"].run_cycle()

    detail = appliance["client"].get("/api/devices/10.0.0.5").get_json()
    assert detail["isolation"]["enforced"] is False
    assert detail["isolation"]["status"] == "Requested / not enforced"


def test_a_device_with_no_isolation_state_reports_not_requested(appliance) -> None:
    appliance["results"].append(([_assessment("10.0.0.5")], []))

    appliance["worker"].run_cycle()

    detail = appliance["client"].get("/api/devices/10.0.0.5").get_json()
    assert detail["isolation"]["status"] == "Not requested"


def test_an_updated_isolation_state_replaces_the_previous_one(appliance) -> None:
    noop = IsolationStatus(True, False, "noop", "unavailable", TS, False)
    enforced = IsolationStatus(True, True, "linux-iptables", "isolated", TS, True)
    appliance["results"].extend(
        [
            ([_assessment("10.0.0.5", isolation=noop)], []),
            ([_assessment("10.0.0.5", isolation=enforced)], []),
        ]
    )

    appliance["worker"].run_cycle()
    appliance["worker"].run_cycle()

    detail = appliance["client"].get("/api/devices/10.0.0.5").get_json()
    assert detail["isolation"]["status"] == "Enforced"


# --- reports through the API ---------------------------------------------


def test_a_generated_report_becomes_visible(appliance) -> None:
    appliance["results"].append(([_assessment("10.0.0.5")], [_report("10.0.0.5", "CIPHER-one")]))

    appliance["worker"].run_cycle()

    summary = appliance["client"].get("/api/devices").get_json()["devices"][0]
    assert summary["has_report"] is True

    report = appliance["client"].get("/api/devices/10.0.0.5/report").get_json()
    assert report["report_id"] == "CIPHER-one"
    assert report["download_url"] == "/api/devices/10.0.0.5/report/download"


def test_the_latest_report_per_device_is_served(appliance) -> None:
    """Repeated cycles regenerate a flagged device's report; the API serves
    the newest one."""
    appliance["results"].extend(
        [
            ([_assessment("10.0.0.5")], [_report("10.0.0.5", "CIPHER-first")]),
            ([_assessment("10.0.0.5")], [_report("10.0.0.5", "CIPHER-second")]),
        ]
    )

    appliance["worker"].run_cycle()
    appliance["worker"].run_cycle()

    report = appliance["client"].get("/api/devices/10.0.0.5/report").get_json()
    assert report["report_id"] == "CIPHER-second"
    assert appliance["client"].get("/api/health").get_json()["reports_generated"] == 1


def test_a_device_without_a_report_404s_on_the_report_endpoint(appliance) -> None:
    appliance["results"].append(([_assessment("10.0.0.5")], []))

    appliance["worker"].run_cycle()

    assert appliance["client"].get("/api/devices/10.0.0.5/report").status_code == 404


# --- availability during failures ----------------------------------------


def test_a_failed_cycle_leaves_the_api_serving_the_previous_state(appliance) -> None:
    appliance["results"].append(([_assessment("10.0.0.5")], [_report("10.0.0.5")]))
    appliance["worker"].run_cycle()

    def _failing(capture_source, **kwargs):
        raise CaptureError("interface disappeared")

    appliance["worker"]._run_capture = _failing
    appliance["worker"].run_cycle()

    devices = appliance["client"].get("/api/devices").get_json()["devices"]
    assert [d["device_ip"] for d in devices] == ["10.0.0.5"]
    assert devices[0]["has_report"] is True


def test_the_api_keeps_serving_while_a_worker_thread_publishes(appliance) -> None:
    """Concurrency as the appliance actually runs it: a worker thread
    republishing while request threads read."""
    worker = appliance["worker"]
    client = appliance["client"]
    errors: List[Exception] = []
    published = {"count": 0}

    def _publishing(capture_source, **kwargs):
        published["count"] += 1
        index = published["count"]
        if index >= 40:
            worker.stop()
        return ([_assessment(f"10.2.0.{index % 250}")], [])

    worker._run_capture = _publishing
    thread = threading.Thread(target=lambda: worker.run_forever(sleep=lambda _s: None))
    thread.start()
    try:
        for _ in range(60):
            try:
                response = client.get("/api/devices")
                assert response.status_code == 200
                response.get_json()
            except Exception as exc:  # pragma: no cover - a failure is the finding
                errors.append(exc)
    finally:
        worker.stop()
        thread.join(timeout=20)

    assert errors == []
    assert worker.cycles_completed >= 1
