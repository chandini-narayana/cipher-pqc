"""ApplicationState — the small, in-memory snapshot of one completed
offline run that the REST API serves from.

Populated exactly once, by run_api.py, from run_capture()'s return
value — never recomputed, never a database, never DeviceRegistry.
Provides explicit mappings only:

    device IP -> DeviceAssessment
    device IP -> (Path, ReportMetadata)

The API must never construct a filesystem path from user input: every
route resolves a device IP through this state's dict lookups only,
returning 404 for an unknown key rather than ever touching the
filesystem with a client-supplied string (see docs/SDD.md's Phase 12
addendum).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from models.device_assessment import DeviceAssessment
from models.report_metadata import ReportMetadata


@dataclass(frozen=True)
class ApplicationState:
    """Immutable snapshot built once from run_capture()'s results."""

    assessments_by_ip: Dict[str, DeviceAssessment] = field(default_factory=dict)
    reports_by_ip: Dict[str, Tuple[Path, ReportMetadata]] = field(default_factory=dict)

    @property
    def devices_assessed(self) -> int:
        return len(self.assessments_by_ip)

    @property
    def reports_generated(self) -> int:
        return len(self.reports_by_ip)

    def get_assessment(self, ip: str) -> Optional[DeviceAssessment]:
        return self.assessments_by_ip.get(ip)

    def get_report(self, ip: str) -> Optional[Tuple[Path, ReportMetadata]]:
        return self.reports_by_ip.get(ip)

    def list_assessments(self) -> List[DeviceAssessment]:
        """All retained assessments, ordered deterministically by IP."""
        return [self.assessments_by_ip[ip] for ip in sorted(self.assessments_by_ip)]


def build_application_state(
    assessments: List[DeviceAssessment],
    reports: List[Tuple[Path, ReportMetadata]],
) -> ApplicationState:
    """Build an ApplicationState from run_capture()'s exact return
    shape — (List[DeviceAssessment], List[Tuple[Path, ReportMetadata]])."""
    assessments_by_ip = {assessment.device.ip: assessment for assessment in assessments}
    reports_by_ip = {metadata.device_ip: (path, metadata) for path, metadata in reports}
    return ApplicationState(assessments_by_ip=assessments_by_ip, reports_by_ip=reports_by_ip)
