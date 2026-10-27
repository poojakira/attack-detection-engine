"""Per-function unit tests for healthcare helper and branch functions.

Complements the behavioral tests in test_healthcare_*.py with direct,
function-level coverage of helpers, edge branches, and small utilities so that
each function has at least one dedicated assertion.
"""

from datetime import datetime, timezone

import pytest

from detection_engine.healthcare import schema as schema_mod
from detection_engine.healthcare.schema import ClinicalAccessEvent
from detection_engine.healthcare.context import ActorProfile, ClinicalContext
from detection_engine.healthcare.synthetic import (
    SyntheticAccessGenerator,
    _session_token,
)
from detection_engine.healthcare.detector import PatientAccessDetector
from detection_engine.healthcare.mimic.adapter import (
    MimicLoadReport,
    MimicDemoAdapter,
    compute_sha256,
    gzip_csv_bytes,
)


# --- schema helpers ---------------------------------------------------------

class TestSchemaHelpers:
    def test_looks_like_pii_email(self):
        assert schema_mod._looks_like_pii("a@b.co") is not None

    def test_looks_like_pii_ssn(self):
        assert "SSN" in schema_mod._looks_like_pii("123-45-6789")

    def test_looks_like_pii_bare_mrn(self):
        assert schema_mod._looks_like_pii("123456789") is not None

    def test_looks_like_pii_clean(self):
        assert schema_mod._looks_like_pii("clin-001") is None

    def test_ref_token_prefers_reference(self):
        assert schema_mod._ref_token({"reference": "Patient/pat-1"}) == "pat-1"

    def test_ref_token_falls_back_to_identifier(self):
        assert schema_mod._ref_token({"identifier": {"value": "id-9"}}) == "id-9"

    def test_ref_token_empty(self):
        assert schema_mod._ref_token({}) == ""

    def test_from_dict_builds_event(self):
        e = ClinicalAccessEvent.from_dict(
            {
                "actor_id": "a",
                "patient_ref": "p",
                "resource_id": "r",
                "action": "read",
                "timestamp": "2026-10-27T09:00:00",
            }
        )
        assert isinstance(e, ClinicalAccessEvent)

    def test_export_zero_records_rejected(self):
        with pytest.raises(Exception):
            ClinicalAccessEvent(
                actor_id="a", patient_ref="p", resource_id="r",
                action="export", record_count=0,
                timestamp=datetime(2026, 10, 27),
            )


# --- context ----------------------------------------------------------------

class TestContextFunctions:
    def _profile(self, **kw):
        base = dict(actor_id="a", actor_type="nurse", role="rn", department="x")
        base.update(kw)
        return ActorProfile(**base)

    def test_is_on_shift_day_window(self):
        p = self._profile(shift=(7, 19))
        assert p.is_on_shift(datetime(2026, 10, 27, 10, tzinfo=timezone.utc))
        assert not p.is_on_shift(datetime(2026, 10, 27, 3, tzinfo=timezone.utc))

    def test_is_on_shift_crosses_midnight(self):
        p = self._profile(shift=(19, 7))
        assert p.is_on_shift(datetime(2026, 10, 27, 23, tzinfo=timezone.utc))
        assert p.is_on_shift(datetime(2026, 10, 27, 3, tzinfo=timezone.utc))
        assert not p.is_on_shift(datetime(2026, 10, 27, 12, tzinfo=timezone.utc))

    def test_is_assigned(self):
        p = self._profile(assigned_patients={"pt-1"})
        assert p.is_assigned("pt-1")
        assert not p.is_assigned("pt-2")

    def test_has_care_relationship(self):
        p = self._profile(care_relationships={"pt-9"})
        assert p.has_care_relationship("pt-9")
        assert not p.has_care_relationship("pt-1")

    def test_resource_scope_no_restriction_allows_all(self):
        p = self._profile()
        assert p.is_resource_in_scope("anything")

    def test_resource_scope_enforced(self):
        p = self._profile(authorized_resource_prefixes={"res-lab-"})
        assert p.is_resource_in_scope("res-lab-1")
        assert not p.is_resource_in_scope("res-billing-1")

    def test_clinical_context_profile_lookup(self):
        ctx = ClinicalContext(actors={"a": self._profile()})
        assert ctx.profile("a") is not None
        assert ctx.profile("missing") is None

    def test_from_synthetic_org_roundtrip(self):
        org = SyntheticAccessGenerator(seed=1).build_org()
        ctx = ClinicalContext.from_synthetic_org(org)
        assert set(ctx.actors) == set(org.actors)


# --- synthetic --------------------------------------------------------------

class TestSyntheticFunctions:
    def test_session_token_is_pseudonymous_and_stable(self):
        ts = datetime(2026, 10, 27, 9, tzinfo=timezone.utc)
        t1 = _session_token("clin-001", ts)
        t2 = _session_token("clin-001", ts)
        assert t1 == t2 and t1.startswith("sess-")

    def test_org_is_on_shift(self):
        org = SyntheticAccessGenerator(seed=1).build_org()
        aid = next(iter(org.actors))
        # Should not raise and returns a bool
        assert isinstance(
            org.is_on_shift(aid, datetime(2026, 10, 27, 10, tzinfo=timezone.utc)), bool
        )

    def test_build_org_has_service_accounts(self):
        org = SyntheticAccessGenerator(seed=1).build_org()
        svc = [a for a in org.actors.values() if a.actor_type.value == "service_account"]
        assert svc

    @pytest.mark.parametrize(
        "method",
        [
            "benign_rounds",
            "benign_emergency_access",
            "benign_service_account",
            "attack_off_shift_unassigned",
            "attack_denied_then_success",
            "attack_service_account_scope_violation",
            "attack_bulk_export",
        ],
    )
    def test_scenario_methods_return_synthetic_events(self, method):
        gen = SyntheticAccessGenerator(seed=1)
        org = gen.build_org()
        events = getattr(gen, method)(org)
        assert events
        assert all(e.data_origin == "synthetic" for e in events)

    def test_attack_bulk_access_count(self):
        gen = SyntheticAccessGenerator(seed=1)
        org = gen.build_org()
        assert len(gen.attack_bulk_access(org, 15)) == 15


# --- detector ---------------------------------------------------------------

class TestDetectorFunctions:
    def test_coerce_accepts_objects_and_dicts(self):
        det = PatientAccessDetector()
        ev = ClinicalAccessEvent(
            actor_id="a", patient_ref="p", resource_id="r", action="read",
            timestamp=datetime(2026, 10, 27),
        )
        coerced = det._coerce([ev, ev.model_dump(mode="json")])
        assert len(coerced) == 2
        assert all(isinstance(e, ClinicalAccessEvent) for e in coerced)

    def test_empty_batch_no_findings(self):
        assert PatientAccessDetector().detect([]) == []

    def test_break_glass_rule_isolated(self):
        det = PatientAccessDetector()
        ev = ClinicalAccessEvent(
            actor_id="a", patient_ref="p", resource_id="r", action="read",
            break_glass=True, timestamp=datetime(2026, 10, 27),
        )
        findings = det.detect([ev.model_dump(mode="json")])
        assert any(f.rule_id == "HC-ACCESS-BREAKGLASS" for f in findings)

    def test_denied_then_success_requires_streak(self):
        det = PatientAccessDetector(denial_streak_threshold=3)
        base = dict(actor_id="a", patient_ref="p", resource_id="r")
        evs = []
        for i in range(2):  # only 2 denials < threshold
            evs.append(ClinicalAccessEvent(action="read", outcome="denied",
                       timestamp=datetime(2026, 10, 27, 0, i), **base).model_dump(mode="json"))
        evs.append(ClinicalAccessEvent(action="read", outcome="success",
                   timestamp=datetime(2026, 10, 27, 0, 5), **base).model_dump(mode="json"))
        assert not [f for f in det.detect(evs) if f.rule_id == "HC-ACCESS-DENYSUCCESS"]


# --- mimic adapter helpers --------------------------------------------------

class TestAdapterHelpers:
    def test_compute_sha256_matches_hashlib(self):
        import hashlib
        data = b"hello"
        assert compute_sha256(data) == hashlib.sha256(data).hexdigest()

    def test_gzip_csv_bytes_roundtrip(self):
        import csv
        import gzip
        import io
        blob = gzip_csv_bytes(["a", "b"], [["1", "2"]])
        rows = list(csv.reader(io.StringIO(gzip.decompress(blob).decode())))
        assert rows[0] == ["a", "b"]
        assert rows[1] == ["1", "2"]

    def test_patient_token(self):
        assert MimicDemoAdapter._patient_token("1001") == "pt-1001"

    def test_load_report_as_dict_shape(self):
        rep = MimicLoadReport(patient_count=3, admission_count=5, provider_count=2)
        d = rep.as_dict()
        assert d["patient_count"] == 3
        assert d["admission_count"] == 5
        assert "license" in d and "doi" in d
