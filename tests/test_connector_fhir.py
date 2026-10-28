"""Milestone E: FHIR R4 AuditEvent connector tests (unit + real-PG/HTTP e2e)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("AEGIS_JWT_SECRET", "milestone-e-test-secret-at-least-32-chars")
TEST_DB_URL = os.environ.get(
    "AEGIS_TEST_DATABASE_URL", "postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
)
os.environ.setdefault("AEGIS_DATABASE_URL", TEST_DB_URL)

from detection_engine.platform.connectors.base import ConnectorError  # noqa: E402
from detection_engine.platform.connectors.fhir_auditevent import (  # noqa: E402
    FhirAuditEventConnector,
)


def _audit_event(event_id="ae-1", actor="Practitioner/prac-7", patient="Patient/pat-3",
                 action="R", outcome="0", recorded="2026-10-27T10:00:00Z", display="Dr Real Name"):
    return {
        "resourceType": "AuditEvent",
        "id": event_id,
        "type": {"system": "http://dicom.nema.org/resources/ontology/DCM", "code": "110110"},
        "subtype": [{"code": "ITI-41"}],
        "action": action,
        "recorded": recorded,
        "outcome": outcome,
        "agent": [{"who": {"reference": actor, "display": display},
                   "network": {"address": "10.0.0.9", "type": "2"}}],
        "source": {"observer": {"reference": "Device/dev-1"}},
        "entity": [{"what": {"reference": patient}},
                   {"what": {"reference": "Observation/obs-9"}}],
    }


# --- unit: parsing / validation / normalization ----------------------------

class TestFhirConnectorParsing:
    def _c(self):
        return FhirAuditEventConnector()

    def test_single_resource(self):
        r = self._c().parse(_audit_event(), organization_id="org-a", max_items=100)
        assert len(r.events) == 1 and not r.errors
        e = r.events[0]
        assert e.source_type == "fhir_audit_event"
        assert e.identity_id == "prac-7"         # token, not the display name
        assert e.resource_reference in ("pat-3", "obs-9")
        assert e.action == "read" and e.outcome == "success"
        assert e.organization_id == "org-a"

    def test_display_name_never_leaks(self):
        r = self._c().parse(_audit_event(display="SECRET PATIENT NAME"),
                            organization_id="org-a", max_items=100)
        e = r.events[0]
        blob = str(e.model_dump())
        assert "SECRET PATIENT NAME" not in blob

    def test_bundle_of_auditevents(self):
        bundle = {
            "resourceType": "Bundle", "type": "collection",
            "entry": [
                {"resource": _audit_event(event_id="ae-1")},
                {"resource": _audit_event(event_id="ae-2")},
                {"resource": {"resourceType": "Patient", "id": "p1"}},  # ignored
            ],
        }
        r = self._c().parse(bundle, organization_id="org-a", max_items=100)
        assert len(r.events) == 2

    def test_list_of_resources(self):
        r = self._c().parse([_audit_event("a"), _audit_event("b")],
                            organization_id="org-a", max_items=100)
        assert len(r.events) == 2

    def test_missing_recorded_rejected(self):
        bad = _audit_event()
        del bad["recorded"]
        r = self._c().parse(bad, organization_id="org-a", max_items=100)
        assert len(r.events) == 0 and len(r.errors) == 1
        assert "recorded" in r.errors[0]["error"]

    def test_invalid_timestamp_rejected(self):
        r = self._c().parse(_audit_event(recorded="not-a-date"),
                            organization_id="org-a", max_items=100)
        assert len(r.errors) == 1

    def test_missing_agent_rejected(self):
        bad = _audit_event()
        del bad["agent"]
        r = self._c().parse(bad, organization_id="org-a", max_items=100)
        assert len(r.errors) == 1

    def test_unsupported_resource_type_raises(self):
        with pytest.raises(ConnectorError):
            self._c().parse({"resourceType": "Observation"}, organization_id="org-a", max_items=100)

    def test_non_object_payload_raises(self):
        with pytest.raises(ConnectorError):
            self._c().parse("garbage", organization_id="org-a", max_items=100)

    def test_mixed_valid_and_invalid_isolated(self):
        bad = _audit_event("bad")
        del bad["recorded"]
        r = self._c().parse([_audit_event("ok"), bad],
                            organization_id="org-a", max_items=100)
        assert len(r.events) == 1 and len(r.errors) == 1  # error isolation

    def test_max_items_enforced(self):
        with pytest.raises(ConnectorError):
            self._c().parse([_audit_event(str(i)) for i in range(10)],
                            organization_id="org-a", max_items=5)

    def test_org_from_caller_not_payload(self):
        # Even if a hostile payload embedded an org, the connector uses caller's.
        ae = _audit_event()
        ae["organization_id"] = "org-evil"  # ignored (not a FHIR field)
        r = self._c().parse(ae, organization_id="org-a", max_items=100)
        assert r.events[0].organization_id == "org-a"


# --- e2e: FHIR -> API -> detect -> correlate -> persist -> retrieve --------

def _pg_http() -> bool:
    try:
        import fastapi  # noqa: F401
        from sqlalchemy import text

        import attack_v19_core  # noqa: F401
        from detection_engine.platform import db as _db

        e = _db.make_engine(TEST_DB_URL)
        with e.connect() as c:
            c.execute(text("SELECT 1"))
        e.dispose()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _pg_http(), reason="requires PostgreSQL + fastapi + core")
class TestFhirEndToEnd:
    @pytest.fixture()
    def client(self):
        from fastapi.testclient import TestClient

        from detection_engine.platform import db as _db
        from detection_engine.platform.bootstrap import build_app, seed_user
        from detection_engine.healthcare.context import ActorProfile, ClinicalContext

        eng = _db.make_engine(TEST_DB_URL)
        _db.Base.metadata.drop_all(eng)
        _db.Base.metadata.create_all(eng)
        s = _db.make_session_factory(eng)()
        seed_user(s, user_id="u1", username="ana", password="pw-strong-12345",
                  role="security_analyst", organization_id="org-a")
        s.close()
        # prac-7 assigned to pat-0001/pat-0002 only -> bulk reads of others anomalous
        ctx = ClinicalContext(actors={
            "prac-7": ActorProfile(actor_id="prac-7", actor_type="clinician",
                                   role="attending", department="cardiology",
                                   assigned_patients={"pat-0001", "pat-0002"}, shift=(0, 24))
        })
        yield TestClient(build_app(clinical_context=ctx)), eng
        eng.dispose()

    def _tok(self, c):
        return c.post("/api/v1/auth/token", json={"username": "ana", "password": "pw-strong-12345"}).json()["access_token"]

    def test_single_fhir_event_ingested(self, client):
        c, _ = client
        tok = self._tok(c)
        r = c.post("/api/v1/connectors/fhir/auditevent", json=_audit_event(),
                   headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 1
        assert body["connector"]["source_type"] == "fhir_audit_event"
        assert body["connector"]["rejected"] == 0

    def test_fhir_bundle_bulk_triggers_incident(self, client):
        c, _ = client
        tok = self._tok(c)
        base = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
        # 40 FHIR AuditEvents: prac-7 reading many UNASSIGNED patients -> anomaly
        entries = [
            {"resource": _audit_event(
                event_id=f"ae-{i}",
                patient=f"Patient/pat-9{i:03d}",
                recorded=(base + timedelta(seconds=10 * i)).isoformat().replace("+00:00", "Z"),
            )}
            for i in range(40)
        ]
        bundle = {"resourceType": "Bundle", "type": "collection", "entry": entries}
        r = c.post("/api/v1/connectors/fhir/auditevent", json=bundle,
                   headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 40
        assert body["incident_ids"], "bulk FHIR access should correlate an incident"
        # Retrieve and verify via the existing investigation API
        inc = c.get(f"/api/v1/incidents/{body['incident_ids'][0]}",
                    headers={"Authorization": f"Bearer {tok}"}).json()
        assert inc["severity"] in {"HIGH", "CRITICAL", "MEDIUM"}
        ev = c.get(f"/api/v1/incidents/{body['incident_ids'][0]}/evidence",
                   headers={"Authorization": f"Bearer {tok}"}).json()
        # No clinical display-name content in evidence
        assert "Real Name" not in str(ev)

    def test_invalid_fhir_rejected_not_crash(self, client):
        c, _ = client
        tok = self._tok(c)
        r = c.post("/api/v1/connectors/fhir/auditevent",
                   json={"resourceType": "Observation"},
                   headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 422

    def test_fhir_duplicate_event_deduped(self, client):
        c, _ = client
        tok = self._tok(c)
        ae = _audit_event(event_id="dup-ae-1")
        h = {"Authorization": f"Bearer {tok}"}
        r1 = c.post("/api/v1/connectors/fhir/auditevent", json=ae, headers=h).json()
        r2 = c.post("/api/v1/connectors/fhir/auditevent", json=ae, headers=h).json()
        assert r1["accepted"] == 1
        assert r2["accepted"] == 0 and r2["duplicates"] == 1
