"""Unit tests for the platform investigation data model."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from detection_engine.base import DetectionFinding
from detection_engine.platform.models import (
    SCHEMA_VERSION,
    DataOrigin,
    DetectionFindingRecord,
    IncidentSeverity,
    IncidentStatus,
    InvestigationAction,
    InvestigationActionType,
    SecurityEvent,
    SecurityIncident,
)


class TestSecurityEvent:
    def _evt(self, **kw):
        base = dict(source_type="clinical_access", event_timestamp=datetime(2026, 10, 27, 9, 0))
        base.update(kw)
        return SecurityEvent(**base)

    def test_defaults_and_schema_version(self):
        e = self._evt()
        assert e.schema_version == SCHEMA_VERSION
        assert e.event_id.startswith("evt-")
        assert e.data_origin == DataOrigin.UNSPECIFIED
        assert e.organization_id == "default"

    def test_timestamps_normalized_to_utc(self):
        e = self._evt(event_timestamp=datetime(2026, 10, 27, 9, 0))
        assert e.event_timestamp.tzinfo == timezone.utc
        assert e.ingestion_timestamp.tzinfo == timezone.utc

    def test_null_fields_allowed(self):
        e = self._evt()
        assert e.identity_id is None and e.resource_reference is None

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            self._evt(patient_name="John")

    def test_dedup_key_uses_source_event_id(self):
        a = self._evt(source_event_id="S1", identity_id="x")
        b = self._evt(source_event_id="S1", identity_id="y")  # different identity
        # same source_event_id+org+source_type -> same dedup key (true replay)
        assert a.dedup_key() == b.dedup_key()

    def test_dedup_key_content_hash_when_no_source_id(self):
        a = self._evt(identity_id="x", resource_reference="r", action="read")
        b = self._evt(identity_id="z", resource_reference="r", action="read")
        # different identity, no source id -> different dedup key (not merged)
        assert a.dedup_key() != b.dedup_key()

    def test_dedup_key_distinct_orgs(self):
        a = self._evt(source_event_id="S1", organization_id="org-a")
        b = self._evt(source_event_id="S1", organization_id="org-b")
        assert a.dedup_key() != b.dedup_key()


class TestDetectionFindingRecord:
    def _engine_finding(self, severity="HIGH", mappings=None):
        return DetectionFinding(
            rule_id="HC-ACCESS-BULK",
            rule_name="Bulk access",
            severity=severity,
            confidence=0.8,
            source_type="clinical_access",
            raw_evidence={"actor_id": "clin-1", "resource_id": "res-9", "patient_name": None},
            mappings=mappings or [],
            timestamp="2026-10-27T10:00:00+00:00",
            host="ws-1",
            description="bulk access",
        )

    def test_from_engine_finding_maps_core_fields(self):
        rec = DetectionFindingRecord.from_engine_finding(
            self._engine_finding(), organization_id="org-a", rule_version="v1"
        )
        assert rec.rule_id == "HC-ACCESS-BULK"
        assert rec.severity == IncidentSeverity.HIGH
        assert rec.confidence == 0.8
        assert rec.organization_id == "org-a"
        assert rec.rule_version == "v1"
        assert rec.affected_identity == "clin-1"
        assert rec.affected_resource == "res-9"

    def test_from_engine_finding_extracts_attack_techniques(self):
        class _M:
            technique_id = "T1567"

        rec = DetectionFindingRecord.from_engine_finding(
            self._engine_finding(mappings=[_M()])
        )
        assert rec.mapped_attack_techniques == ["T1567"]

    def test_unknown_severity_defaults_to_info(self):
        rec = DetectionFindingRecord.from_engine_finding(
            self._engine_finding(severity="WEIRD")
        )
        assert rec.severity == IncidentSeverity.INFO

    def test_finding_id_generated(self):
        rec = DetectionFindingRecord.from_engine_finding(self._engine_finding())
        assert rec.finding_id.startswith("fnd-")


class TestSeverityAndStatus:
    def test_severity_rank_order(self):
        assert IncidentSeverity.CRITICAL.rank > IncidentSeverity.HIGH.rank
        assert IncidentSeverity.HIGH.rank > IncidentSeverity.MEDIUM.rank
        assert IncidentSeverity.LOW.rank > IncidentSeverity.INFO.rank

    def test_status_values(self):
        assert {s.value for s in IncidentStatus} == {
            "NEW", "TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED"
        }


class TestSecurityIncident:
    def test_defaults(self):
        inc = SecurityIncident(title="t", severity=IncidentSeverity.HIGH)
        assert inc.incident_id.startswith("inc-")
        assert inc.status == IncidentStatus.NEW
        assert inc.created_at.tzinfo == timezone.utc

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            SecurityIncident(title="t", severity=IncidentSeverity.HIGH, secret="x")


class TestInvestigationAction:
    def test_action_record(self):
        a = InvestigationAction(
            incident_id="inc-1",
            analyst_id="analyst-1",
            action_type=InvestigationActionType.ADD_NOTE,
            note="looked at evidence",
        )
        assert a.action_id.startswith("act-")
        assert a.action_type == InvestigationActionType.ADD_NOTE
        assert a.timestamp.tzinfo == timezone.utc

    def test_status_change_records_previous_and_updated(self):
        a = InvestigationAction(
            incident_id="inc-1",
            analyst_id="analyst-1",
            action_type=InvestigationActionType.STATUS_CHANGE,
            previous_value="NEW",
            updated_value="INVESTIGATING",
        )
        assert a.previous_value == "NEW"
        assert a.updated_value == "INVESTIGATING"
