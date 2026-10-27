"""Ingestion orchestration service.

Ties the normalized ``SecurityEvent`` model to the existing ``DetectionPipeline``
and the persistence/correlation layers:

    normalize -> persist event (idempotent) -> detect -> persist findings ->
    correlate -> upsert incident (idempotent)

This is framework-agnostic so it is unit-testable without HTTP. The FastAPI app
is a thin authenticated layer over it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from .correlation import CorrelationEngine
from .models import (
    DetectionFindingRecord,
    SecurityEvent,
)
from .repository import Repository

# Which engine telemetry source each SecurityEvent.source_type maps to.
# Only clinical_access is wired for findings in this milestone; other sources
# are accepted and persisted but not force-fit through healthcare detection.
_HEALTHCARE_SOURCE = "clinical_access"


def _clinical_fields(record: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw ingest record onto the fields ClinicalAccessEvent accepts.

    Platform-only keys (e.g. source_event_id) are dropped so the strict,
    extra-forbidden clinical schema does not reject a valid record.
    """
    from ..healthcare.schema import ClinicalAccessEvent

    allowed = set(ClinicalAccessEvent.model_fields.keys())
    return {k: v for k, v in record.items() if k in allowed}


@dataclass
class IngestResult:
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    event_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    incident_ids: List[str] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "rejected": self.rejected,
            "event_ids": self.event_ids,
            "finding_ids": self.finding_ids,
            "incident_ids": self.incident_ids,
            "errors": self.errors,
        }


class IngestionService:
    def __init__(
        self,
        session: Session,
        pipeline: Any,
        *,
        correlation_engine: Optional[CorrelationEngine] = None,
        clinical_detector: Any = None,
    ):
        self.repo = Repository(session)
        self.session = session
        self.pipeline = pipeline
        self.correlation = correlation_engine or CorrelationEngine()
        # Optional direct detector (used when pipeline needs clinical context the
        # app injected); falls back to pipeline.run otherwise.
        self.clinical_detector = clinical_detector

    def ingest(
        self, raw_events: List[Dict[str, Any]], *, organization_id: str
    ) -> IngestResult:
        result = IngestResult()
        detected_findings: List[DetectionFindingRecord] = []
        event_ids_by_finding: Dict[str, List[str]] = {}

        for idx, raw in enumerate(raw_events):
            try:
                event = self._normalize(raw, organization_id)
            except Exception as exc:  # validation / schema error
                result.rejected += 1
                result.errors.append({"index": idx, "error": str(exc)})
                continue

            row, created = self.repo.upsert_event(event)
            if not created:
                result.duplicates += 1
                continue
            result.accepted += 1
            result.event_ids.append(row.event_id)

            # Run detection for healthcare clinical-access events.
            if event.source_type == _HEALTHCARE_SOURCE:
                for rec in self._detect_clinical(event, raw, organization_id):
                    self.repo.add_finding(rec)
                    detected_findings.append(rec)
                    result.finding_ids.append(rec.finding_id)
                    event_ids_by_finding.setdefault(rec.finding_id, []).append(row.event_id)

        # Correlate the batch's findings and persist incidents idempotently.
        for ci in self.correlation.correlate(
            detected_findings, event_ids_by_finding=event_ids_by_finding
        ):
            inc_row, _ = self.repo.upsert_incident(
                ci.incident, finding_ids=ci.finding_ids, event_ids=ci.event_ids
            )
            if inc_row.incident_id not in result.incident_ids:
                result.incident_ids.append(inc_row.incident_id)

        self.session.commit()
        return result

    # --- normalization ------------------------------------------------------

    def _normalize(self, raw: Dict[str, Any], organization_id: str) -> SecurityEvent:
        """Build a validated SecurityEvent. Unknown/invalid payloads raise."""
        data = dict(raw)
        data["organization_id"] = organization_id  # org from the authenticated caller
        # Accept a FHIR AuditEvent envelope and normalize it.
        if data.get("source_type") == "fhir_audit_event" and "fhir" in data:
            return self._from_fhir(data["fhir"], organization_id, data.get("source_event_id"))
        return SecurityEvent.model_validate(data)

    def _from_fhir(self, fhir: Dict[str, Any], organization_id: str, source_event_id):
        from ..healthcare.schema import ClinicalAccessEvent

        cae = ClinicalAccessEvent.from_fhir_audit_event(fhir)
        return SecurityEvent(
            source_type=_HEALTHCARE_SOURCE,
            source_event_id=source_event_id,
            event_timestamp=cae.timestamp,
            identity_id=cae.actor_id,
            session_id=cae.session_id or None,
            host_id=cae.source_host or None,
            resource_reference=cae.resource_id,
            action=cae.action.value,
            outcome=cae.outcome.value,
            organization_id=organization_id,
            data_origin="demo_derived",
            normalized_attributes=cae.redacted_evidence(),
        )

    # --- detection ----------------------------------------------------------

    def _detect_clinical(
        self, event: SecurityEvent, raw: Dict[str, Any], organization_id: str
    ) -> List[DetectionFindingRecord]:
        """Run the clinical-access detector for a single event.

        The detector operates on a batch; here we pass the single event's
        normalized attributes. Batch/stateful rules (bulk, denial-streak) fire
        when multiple events are ingested together via the pipeline path.
        """
        if self.clinical_detector is None:
            return []
        clinical_record = _clinical_fields(dict(event.normalized_attributes))
        # Ensure required clinical fields are present for the detector.
        clinical_record.setdefault("actor_id", event.identity_id or "unknown")
        clinical_record.setdefault("patient_ref", event.resource_reference or "unknown")
        clinical_record.setdefault("resource_id", event.resource_reference or "unknown")
        clinical_record.setdefault("action", event.action or "read")
        clinical_record.setdefault("outcome", event.outcome or "success")
        clinical_record.setdefault("timestamp", event.event_timestamp.isoformat())
        findings = self.clinical_detector.detect([clinical_record])
        return [
            DetectionFindingRecord.from_engine_finding(
                f, organization_id=organization_id, source_event_id=event.event_id
            )
            for f in findings
        ]

    def ingest_clinical_batch(
        self, clinical_records: List[Dict[str, Any]], *, organization_id: str
    ) -> IngestResult:
        """Batch path: persist each clinical record as an event AND run the
        batch detector once so stateful rules (bulk access, denial streak) fire.
        """
        result = IngestResult()
        # 1. Persist events
        persisted: List[tuple] = []  # (event_row, raw)
        for idx, rec in enumerate(clinical_records):
            try:
                event = SecurityEvent(
                    source_type=_HEALTHCARE_SOURCE,
                    source_event_id=rec.get("source_event_id"),
                    event_timestamp=rec["timestamp"],
                    identity_id=rec.get("actor_id"),
                    session_id=rec.get("session_id") or None,
                    host_id=rec.get("source_host") or None,
                    resource_reference=rec.get("resource_id"),
                    action=rec.get("action"),
                    outcome=rec.get("outcome"),
                    organization_id=organization_id,
                    data_origin=rec.get("data_origin", "synthetic"),
                    normalized_attributes=rec,
                )
            except Exception as exc:
                result.rejected += 1
                result.errors.append({"index": idx, "error": str(exc)})
                continue
            row, created = self.repo.upsert_event(event)
            if not created:
                result.duplicates += 1
                continue
            result.accepted += 1
            result.event_ids.append(row.event_id)
            persisted.append((row, rec))

        # 2. Run the batch detector once over all accepted records
        detected: List[DetectionFindingRecord] = []
        event_ids_by_finding: Dict[str, List[str]] = {}
        if self.clinical_detector is not None and persisted:
            detector_input = [_clinical_fields(r) for _, r in persisted]
            findings = self.clinical_detector.detect(detector_input)
            # Associate a finding to events by matching actor_id (best-effort,
            # deterministic) so the incident links real event ids.
            actor_to_events: Dict[str, List[str]] = {}
            for row, rec in persisted:
                actor_to_events.setdefault(rec.get("actor_id", ""), []).append(row.event_id)
            for f in findings:
                rec = DetectionFindingRecord.from_engine_finding(
                    f, organization_id=organization_id
                )
                self.repo.add_finding(rec)
                detected.append(rec)
                result.finding_ids.append(rec.finding_id)
                actor = (f.raw_evidence or {}).get("actor_id", "")
                event_ids_by_finding[rec.finding_id] = actor_to_events.get(actor, [])

        # 3. Correlate + persist incidents
        for ci in self.correlation.correlate(detected, event_ids_by_finding=event_ids_by_finding):
            inc_row, _ = self.repo.upsert_incident(
                ci.incident, finding_ids=ci.finding_ids, event_ids=ci.event_ids
            )
            if inc_row.incident_id not in result.incident_ids:
                result.incident_ids.append(inc_row.incident_id)

        self.session.commit()
        return result
