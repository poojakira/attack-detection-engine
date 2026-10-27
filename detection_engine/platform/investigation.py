"""Investigation service: incident state machine + auditable analyst actions.

All incident state changes go through here so that every change is recorded as
an ``InvestigationAction`` (durable audit) and only legal transitions are
allowed. Organization scoping is enforced by passing the caller's
organization_id into every repository call.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from sqlalchemy.orm import Session

from .models import (
    InvestigationAction,
    InvestigationActionType,
    IncidentStatus,
)
from .repository import Repository

# Legal status transitions for the incident lifecycle.
_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
    IncidentStatus.NEW: {IncidentStatus.TRIAGED, IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
    IncidentStatus.TRIAGED: {IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING},
    IncidentStatus.CLOSED: {IncidentStatus.INVESTIGATING},  # reopen
}


class InvalidTransition(ValueError):
    pass


class InvestigationService:
    def __init__(self, session: Session):
        self.session = session
        self.repo = Repository(session)

    def _require(self, incident_id: str, organization_id: str):
        row = self.repo.get_incident(incident_id, organization_id)
        if row is None:
            raise LookupError(f"incident {incident_id} not found")
        return row

    def assign(self, incident_id: str, organization_id: str, *, analyst_id: str, actor: str):
        row = self._require(incident_id, organization_id)
        prev = row.assigned_analyst
        self.repo.update_incident(
            incident_id, organization_id,
            expected_version=row.row_version,
            assigned_analyst=analyst_id,
        )
        self.repo.add_action(InvestigationAction(
            incident_id=incident_id, analyst_id=actor,
            action_type=InvestigationActionType.ASSIGN,
            previous_value=prev, updated_value=analyst_id,
            organization_id=organization_id,
        ))
        self.session.commit()

    def add_note(self, incident_id: str, organization_id: str, *, note: str, actor: str):
        self._require(incident_id, organization_id)
        self.repo.add_action(InvestigationAction(
            incident_id=incident_id, analyst_id=actor,
            action_type=InvestigationActionType.ADD_NOTE,
            note=note, organization_id=organization_id,
        ))
        self.session.commit()

    def change_status(
        self, incident_id: str, organization_id: str, *, new_status: IncidentStatus, actor: str,
        expected_version: Optional[int] = None,
    ):
        row = self._require(incident_id, organization_id)
        current = IncidentStatus(row.status)
        if new_status != current and new_status not in _TRANSITIONS.get(current, set()):
            raise InvalidTransition(f"cannot move incident from {current.value} to {new_status.value}")
        self.repo.update_incident(
            incident_id, organization_id,
            expected_version=expected_version if expected_version is not None else row.row_version,
            status=new_status.value,
        )
        action_type = (
            InvestigationActionType.REOPEN
            if current == IncidentStatus.CLOSED and new_status == IncidentStatus.INVESTIGATING
            else InvestigationActionType.STATUS_CHANGE
        )
        self.repo.add_action(InvestigationAction(
            incident_id=incident_id, analyst_id=actor,
            action_type=action_type,
            previous_value=current.value, updated_value=new_status.value,
            organization_id=organization_id,
        ))
        self.session.commit()

    def record_disposition(self, incident_id: str, organization_id: str, *, disposition: str, summary: str, actor: str):
        row = self._require(incident_id, organization_id)
        self.repo.update_incident(
            incident_id, organization_id,
            expected_version=row.row_version,
            resolution_summary=summary,
        )
        self.repo.add_action(InvestigationAction(
            incident_id=incident_id, analyst_id=actor,
            action_type=InvestigationActionType.DISPOSITION,
            updated_value=disposition, note=summary,
            organization_id=organization_id,
        ))
        self.session.commit()

    def close(self, incident_id: str, organization_id: str, *, reason: str, actor: str):
        row = self._require(incident_id, organization_id)
        current = IncidentStatus(row.status)
        if IncidentStatus.CLOSED not in _TRANSITIONS.get(current, set()) and current != IncidentStatus.CLOSED:
            raise InvalidTransition(f"cannot close from {current.value}")
        self.repo.update_incident(
            incident_id, organization_id,
            expected_version=row.row_version,
            status=IncidentStatus.CLOSED.value, close_reason=reason,
        )
        self.repo.add_action(InvestigationAction(
            incident_id=incident_id, analyst_id=actor,
            action_type=InvestigationActionType.CLOSE,
            previous_value=current.value, updated_value=IncidentStatus.CLOSED.value,
            note=reason, organization_id=organization_id,
        ))
        self.session.commit()

    # --- read: timeline -----------------------------------------------------

    def timeline(self, incident_id: str, organization_id: str) -> List[Dict]:
        """Chronological, distinguishable sequence of events, findings, and
        analyst actions. Returns dicts safe for API serialization."""
        self._require(incident_id, organization_id)
        items: List[Dict] = []
        for ev in self.repo.incident_events(incident_id):
            items.append({
                "kind": "event",
                "timestamp": ev.event_timestamp.isoformat(),
                "ref": ev.event_id,
                "summary": f"{ev.source_type} {ev.action or ''} {ev.outcome or ''}".strip(),
            })
        for f in self.repo.incident_findings(incident_id):
            items.append({
                "kind": "finding",
                "timestamp": f.detection_timestamp.isoformat(),
                "ref": f.finding_id,
                "summary": f"{f.rule_id} [{f.severity}] {f.description}",
            })
        for a in self.repo.incident_actions(incident_id):
            items.append({
                "kind": "analyst_action",
                "timestamp": a.timestamp.isoformat(),
                "ref": a.action_id,
                "summary": f"{a.analyst_id}: {a.action_type}"
                + (f" {a.previous_value}->{a.updated_value}" if a.updated_value else "")
                + (f" note={a.note}" if a.note else ""),
            })
        items.sort(key=lambda x: x["timestamp"])
        return items
