"""Schema, PII-guard, and FHIR-normalization tests for the healthcare module."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from detection_engine.healthcare import (
    AccessAction,
    AccessOutcome,
    ActorType,
    ClinicalAccessEvent,
)


def _base(**overrides):
    data = dict(
        actor_id="clin-001",
        patient_ref="pt-0007",
        resource_id="res-0007-read",
        action="read",
        timestamp=datetime(2026, 10, 27, 9, 0),
    )
    data.update(overrides)
    return data


class TestSchemaValid:
    def test_minimal_valid_event(self):
        e = ClinicalAccessEvent(**_base())
        assert e.action == AccessAction.READ
        assert e.outcome == AccessOutcome.SUCCESS
        assert e.actor_type == ActorType.UNKNOWN

    def test_timestamp_forced_to_utc_from_naive(self):
        e = ClinicalAccessEvent(**_base())
        assert e.timestamp.tzinfo == timezone.utc

    def test_aware_timestamp_converted_to_utc(self):
        from datetime import timedelta

        tz = timezone(timedelta(hours=5))
        e = ClinicalAccessEvent(**_base(timestamp=datetime(2026, 10, 27, 14, 0, tzinfo=tz)))
        # 14:00 +05:00 == 09:00 UTC
        assert e.timestamp.hour == 9
        assert e.timestamp.tzinfo == timezone.utc

    def test_correlation_keys_present(self):
        e = ClinicalAccessEvent(**_base(session_id="sess-abc", source_host="ws-1"))
        keys = e.correlation_keys()
        assert keys["identity"] == "clin-001"
        assert keys["patient"] == "pt-0007"
        assert keys["session"] == "sess-abc"
        assert keys["host"] == "ws-1"

    def test_redacted_evidence_has_no_record_content(self):
        e = ClinicalAccessEvent(**_base())
        ev = e.redacted_evidence()
        # Only metadata + pseudonymous identifiers; no free-text record content.
        assert "patient_name" not in ev
        assert "note" not in ev
        assert ev["patient_ref"] == "pt-0007"
        assert ev["data_origin"] == "unspecified"

    def test_frozen_event_is_immutable(self):
        e = ClinicalAccessEvent(**_base())
        with pytest.raises(ValidationError):
            e.actor_id = "someone-else"


class TestPIIGuard:
    @pytest.mark.parametrize(
        "field,value",
        [
            ("actor_id", "jane.doe@hospital.org"),
            ("patient_ref", "123-45-6789"),
            ("patient_ref", "123456789012"),
            ("resource_id", "patient@example.com"),
            ("session_id", "987654321"),
        ],
    )
    def test_pii_is_rejected(self, field, value):
        with pytest.raises(ValidationError):
            ClinicalAccessEvent(**_base(**{field: value}))

    @pytest.mark.parametrize(
        "field,value",
        [
            ("actor_id", "clin-001"),
            ("patient_ref", "pt-0007"),
            ("resource_id", "res-billing-0001"),
            ("session_id", "sess-5a2b9c"),
        ],
    )
    def test_structured_surrogates_allowed(self, field, value):
        e = ClinicalAccessEvent(**_base(**{field: value}))
        assert getattr(e, field) == value

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            ClinicalAccessEvent(**_base(patient_name="John Doe"))


class TestFHIRNormalization:
    def test_fhir_audit_event_maps_to_pseudonymous_tokens(self):
        fhir = {
            "action": "R",
            "outcome": "0",
            "recorded": "2026-10-27T15:30:00Z",
            "agent": [
                {
                    "who": {"reference": "Practitioner/prac-55", "display": "Dr Real Name"},
                    "network": {"address": "10.0.0.9"},
                }
            ],
            "entity": [
                {"what": {"reference": "Patient/pat-88"}},
                {"what": {"reference": "Observation/obs-3"}},
            ],
            "source": {"reference": "Device/dev-1"},
        }
        e = ClinicalAccessEvent.from_fhir_audit_event(fhir)
        assert e.actor_id == "prac-55"
        assert e.patient_ref == "pat-88"
        assert e.resource_id == "obs-3"
        assert e.resource_type == "Observation"
        assert e.action == AccessAction.READ
        assert e.data_origin == "fhir_audit_event"
        # The human-readable display name must never be carried into the event.
        assert "Real Name" not in e.redacted_evidence().values()
        assert e.actor_id != "Dr Real Name"

    def test_fhir_denied_outcome_maps(self):
        fhir = {
            "action": "R",
            "outcome": "8",
            "recorded": "2026-10-27T15:30:00Z",
            "agent": [{"who": {"reference": "Practitioner/p1"}}],
            "entity": [{"what": {"reference": "Patient/pat-1"}}],
        }
        e = ClinicalAccessEvent.from_fhir_audit_event(fhir)
        assert e.outcome == AccessOutcome.SERIOUS_FAILURE
