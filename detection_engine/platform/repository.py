"""Repository: transaction-safe persistence operations over the ORM.

Encapsulates idempotent event/finding/incident writes, incident updates with
optimistic concurrency, investigation-action audit records, and filtered,
paginated reads. All writes are organization-scoped.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db
from .models import (
    DetectionFindingRecord,
    InvestigationAction,
    SecurityEvent,
    SecurityIncident,
)


class ConcurrencyError(RuntimeError):
    """Raised when an incident update loses an optimistic-concurrency race."""


class Repository:
    def __init__(self, session: Session):
        self.session = session

    # --- Events -------------------------------------------------------------

    def upsert_event(self, event: SecurityEvent) -> Tuple[db.SecurityEventRow, bool]:
        """Insert an event idempotently. Returns (row, created)."""
        dedup = event.dedup_key()
        existing = self.session.execute(
            select(db.SecurityEventRow).where(
                db.SecurityEventRow.organization_id == event.organization_id,
                db.SecurityEventRow.dedup_key == dedup,
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False
        row = db.SecurityEventRow(
            event_id=event.event_id,
            schema_version=event.schema_version,
            source_event_id=event.source_event_id,
            source_type=event.source_type,
            event_timestamp=event.event_timestamp,
            ingestion_timestamp=event.ingestion_timestamp,
            identity_id=event.identity_id,
            session_id=event.session_id,
            host_id=event.host_id,
            resource_reference=event.resource_reference,
            action=event.action,
            outcome=event.outcome,
            organization_id=event.organization_id,
            data_origin=event.data_origin.value,
            source_metadata=event.source_metadata,
            normalized_attributes=event.normalized_attributes,
            dedup_key=dedup,
        )
        self.session.add(row)
        self.session.flush()
        return row, True

    def get_event(self, event_id: str, organization_id: str) -> Optional[db.SecurityEventRow]:
        return self.session.execute(
            select(db.SecurityEventRow).where(
                db.SecurityEventRow.event_id == event_id,
                db.SecurityEventRow.organization_id == organization_id,
            )
        ).scalar_one_or_none()

    # --- Findings -----------------------------------------------------------

    def add_finding(self, finding: DetectionFindingRecord) -> db.DetectionFindingRow:
        row = db.DetectionFindingRow(
            finding_id=finding.finding_id,
            schema_version=finding.schema_version,
            rule_id=finding.rule_id,
            rule_version=finding.rule_version,
            severity=finding.severity.value,
            confidence=finding.confidence,
            description=finding.description,
            evidence_references=finding.evidence_references,
            mapped_attack_techniques=finding.mapped_attack_techniques,
            detection_timestamp=finding.detection_timestamp,
            affected_identity=finding.affected_identity,
            affected_resource=finding.affected_resource,
            disposition=finding.disposition,
            organization_id=finding.organization_id,
            source_event_id=finding.source_event_id,
        )
        self.session.add(row)
        self.session.flush()
        return row

    # --- Incidents ----------------------------------------------------------

    def upsert_incident(
        self,
        incident: SecurityIncident,
        finding_ids: Sequence[str] = (),
        event_ids: Sequence[str] = (),
    ) -> Tuple[db.IncidentRow, bool]:
        """Create or update an incident idempotently by (org, correlation_key).

        On a repeat correlation key, links new findings/events and refreshes
        last_seen/severity instead of creating a duplicate incident.
        """
        existing = None
        if incident.correlation_key is not None:
            existing = self.session.execute(
                select(db.IncidentRow).where(
                    db.IncidentRow.organization_id == incident.organization_id,
                    db.IncidentRow.correlation_key == incident.correlation_key,
                )
            ).scalar_one_or_none()

        if existing is None:
            row = db.IncidentRow(
                incident_id=incident.incident_id,
                schema_version=incident.schema_version,
                title=incident.title,
                description=incident.description,
                severity=incident.severity.value,
                status=incident.status.value,
                created_at=incident.created_at,
                updated_at=incident.updated_at,
                first_seen=incident.first_seen,
                last_seen=incident.last_seen,
                assigned_analyst=incident.assigned_analyst,
                correlation_reason=incident.correlation_reason,
                affected_entities=incident.affected_entities,
                resolution_summary=incident.resolution_summary,
                close_reason=incident.close_reason,
                organization_id=incident.organization_id,
                correlation_key=incident.correlation_key,
            )
            self.session.add(row)
            self.session.flush()
            created = True
        else:
            row = existing
            # Escalate severity if the new evidence is more severe; refresh window.
            from .models import IncidentSeverity

            if IncidentSeverity(incident.severity.value).rank > IncidentSeverity(row.severity).rank:
                row.severity = incident.severity.value
            if incident.last_seen and (row.last_seen is None or incident.last_seen > row.last_seen):
                row.last_seen = incident.last_seen
            row.updated_at = incident.updated_at
            created = False

        self._link_findings(row.incident_id, finding_ids)
        self._link_events(row.incident_id, event_ids)
        self.session.flush()
        return row, created

    def _link_findings(self, incident_id: str, finding_ids: Sequence[str]) -> None:
        for fid in finding_ids:
            exists = self.session.execute(
                select(db.IncidentFindingRow).where(
                    db.IncidentFindingRow.incident_id == incident_id,
                    db.IncidentFindingRow.finding_id == fid,
                )
            ).scalar_one_or_none()
            if exists is None:
                self.session.add(
                    db.IncidentFindingRow(incident_id=incident_id, finding_id=fid)
                )

    def _link_events(self, incident_id: str, event_ids: Sequence[str]) -> None:
        for eid in event_ids:
            exists = self.session.execute(
                select(db.IncidentEventRow).where(
                    db.IncidentEventRow.incident_id == incident_id,
                    db.IncidentEventRow.event_id == eid,
                )
            ).scalar_one_or_none()
            if exists is None:
                self.session.add(
                    db.IncidentEventRow(incident_id=incident_id, event_id=eid)
                )

    def get_incident(self, incident_id: str, organization_id: str) -> Optional[db.IncidentRow]:
        return self.session.execute(
            select(db.IncidentRow).where(
                db.IncidentRow.incident_id == incident_id,
                db.IncidentRow.organization_id == organization_id,
            )
        ).scalar_one_or_none()

    def update_incident(
        self,
        incident_id: str,
        organization_id: str,
        *,
        expected_version: Optional[int] = None,
        **fields,
    ) -> db.IncidentRow:
        """Update incident fields with optimistic concurrency.

        If ``expected_version`` is provided and does not match the stored
        ``row_version``, raises ConcurrencyError (prevents lost updates).
        """
        row = self.get_incident(incident_id, organization_id)
        if row is None:
            raise LookupError(f"incident {incident_id} not found in org {organization_id}")
        if expected_version is not None and row.row_version != expected_version:
            raise ConcurrencyError(
                f"incident {incident_id} changed (expected v{expected_version}, "
                f"found v{row.row_version})"
            )
        for key, value in fields.items():
            setattr(row, key, value)
        row.row_version += 1
        from .models import _utcnow

        row.updated_at = _utcnow()
        self.session.flush()
        return row

    def list_incidents(
        self,
        organization_id: str,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        assigned_analyst: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[db.IncidentRow], int]:
        stmt = select(db.IncidentRow).where(
            db.IncidentRow.organization_id == organization_id
        )
        if status:
            stmt = stmt.where(db.IncidentRow.status == status)
        if severity:
            stmt = stmt.where(db.IncidentRow.severity == severity)
        if assigned_analyst:
            stmt = stmt.where(db.IncidentRow.assigned_analyst == assigned_analyst)
        if since:
            stmt = stmt.where(db.IncidentRow.created_at >= since)
        total = len(self.session.execute(stmt).scalars().all())
        stmt = stmt.order_by(db.IncidentRow.created_at.desc()).limit(limit).offset(offset)
        rows = list(self.session.execute(stmt).scalars().all())
        return rows, total

    def incident_findings(self, incident_id: str) -> List[db.DetectionFindingRow]:
        stmt = (
            select(db.DetectionFindingRow)
            .join(
                db.IncidentFindingRow,
                db.IncidentFindingRow.finding_id == db.DetectionFindingRow.finding_id,
            )
            .where(db.IncidentFindingRow.incident_id == incident_id)
        )
        return list(self.session.execute(stmt).scalars().all())

    def incident_events(self, incident_id: str) -> List[db.SecurityEventRow]:
        stmt = (
            select(db.SecurityEventRow)
            .join(
                db.IncidentEventRow,
                db.IncidentEventRow.event_id == db.SecurityEventRow.event_id,
            )
            .where(db.IncidentEventRow.incident_id == incident_id)
        )
        return list(self.session.execute(stmt).scalars().all())

    # --- Investigation audit ------------------------------------------------

    def add_action(self, action: InvestigationAction) -> db.InvestigationActionRow:
        row = db.InvestigationActionRow(
            action_id=action.action_id,
            incident_id=action.incident_id,
            analyst_id=action.analyst_id,
            action_type=action.action_type.value,
            previous_value=action.previous_value,
            updated_value=action.updated_value,
            note=action.note,
            timestamp=action.timestamp,
            organization_id=action.organization_id,
        )
        self.session.add(row)
        self.session.flush()
        return row

    def incident_actions(self, incident_id: str) -> List[db.InvestigationActionRow]:
        stmt = (
            select(db.InvestigationActionRow)
            .where(db.InvestigationActionRow.incident_id == incident_id)
            .order_by(db.InvestigationActionRow.timestamp.asc())
        )
        return list(self.session.execute(stmt).scalars().all())
