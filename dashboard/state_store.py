"""ApplicationStateStore — the lock-protected publisher that lets the REST
API serve a snapshot while a capture worker produces the next one.

Phase 12 built `ApplicationState` for a single offline run: constructed
once, handed to `create_app`, never changed. Appliance mode (docs/SDD.md's
Phase A1 addendum) keeps that model and adds exactly one thing — a way to
*replace* the published snapshot atomically — because a long-running
appliance assesses devices while the dashboard is already being served.

Two rules make this safe, and they are the whole contract:

  * **Publish by replacement, never by mutation.** A published
    `ApplicationState` is treated as immutable: every publish builds new
    dicts. `ApplicationState` is a frozen dataclass, but it holds ordinary
    mutable dicts, and `list_assessments()` iterates one of them
    (`sorted(self.assessments_by_ip)`) — so mutating a published state
    while a request iterates it could raise "dictionary changed size
    during iteration". Nothing here ever mutates a state that has been
    handed out.
  * **Guard the swap with an explicit lock.** `get()` and every publish
    hold `self._lock` for the single rebind only. The correctness of this
    deliberately does not rest on CPython's GIL making an assignment
    atomic: the lock is the contract, so the behaviour does not depend on
    an interpreter implementation detail.

A reader therefore takes one reference under the lock and then works with
a snapshot that no one will ever modify, with no lock held for the
duration of the request. No database, no persistence, no second state
representation — `utils.registry.DeviceRegistry` remains the unimplemented
stub it has always been.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from models.device_assessment import DeviceAssessment
from models.report_metadata import ReportMetadata
from dashboard.state import ApplicationState

logger = logging.getLogger(__name__)


class ApplicationStateStore:
    """Holds the currently-published ApplicationState behind a lock.

    Constructed with an existing state, or with none at all — the empty
    default is what lets the appliance serve a reachable (if empty)
    dashboard before its first capture cycle has finished.
    """

    def __init__(self, state: Optional[ApplicationState] = None) -> None:
        self._lock = threading.Lock()
        self._state = state if state is not None else ApplicationState()

    def get(self) -> ApplicationState:
        """The currently-published snapshot.

        Safe to use without holding the lock afterwards: the returned
        state is never mutated by a later publish.
        """
        with self._lock:
            return self._state

    def publish(self, state: ApplicationState) -> None:
        """Replace the published snapshot wholesale."""
        with self._lock:
            self._state = state

    def publish_cycle(
        self,
        assessments: Iterable[DeviceAssessment],
        reports: Iterable[Tuple[Path, ReportMetadata]],
    ) -> ApplicationState:
        """Merge one capture cycle's results into the published snapshot
        and return the new state.

        Accumulation rules, chosen so the dashboard behaves like an
        inventory rather than a flickering live view:

          * a device seen for the first time is added;
          * a device seen again replaces its previous entry, so the newest
            assessment (and the isolation state `run_capture` attached to
            it) is what the API serves;
          * a device absent from this cycle is **kept**, because a quiet
            device has not stopped existing — it simply sent nothing in
            the last few seconds;
          * a device's report mapping holds the latest report returned for
            it, keyed exactly as `build_application_state` keys it
            (`metadata.device_ip`).

        Nothing is recomputed here: assessments arrive already assessed,
        already fused and already carrying their isolation state.
        """
        new_assessments: Dict[str, DeviceAssessment] = {}
        new_reports: Dict[str, Tuple[Path, ReportMetadata]] = {}

        with self._lock:
            current = self._state
            # Copy before touching anything: the state currently published
            # may be in use by a request thread right now.
            new_assessments.update(current.assessments_by_ip)
            new_reports.update(current.reports_by_ip)

            added = 0
            replaced = 0
            for assessment in assessments:
                ip = assessment.device.ip
                if ip in new_assessments:
                    replaced += 1
                else:
                    added += 1
                new_assessments[ip] = assessment

            for path, metadata in reports:
                new_reports[metadata.device_ip] = (path, metadata)

            state = ApplicationState(
                assessments_by_ip=new_assessments, reports_by_ip=new_reports
            )
            self._state = state

        logger.debug(
            "Published cycle state: %d device(s) total (%d new, %d updated), %d report(s).",
            len(new_assessments),
            added,
            replaced,
            len(new_reports),
        )
        return state


def resolve_state_store(state: object) -> ApplicationStateStore:
    """Accept either an ApplicationState or an ApplicationStateStore and
    return a store.

    This is what keeps every existing `create_app(state, settings)` caller
    and test working untouched: a plain ApplicationState is wrapped in a
    store that is simply never published to again, which is exactly the
    old "built once, static thereafter" behaviour.
    """
    if isinstance(state, ApplicationStateStore):
        return state
    if isinstance(state, ApplicationState):
        return ApplicationStateStore(state)
    raise TypeError(
        "state must be an ApplicationState or an ApplicationStateStore, got "
        f"{type(state).__name__}"
    )
