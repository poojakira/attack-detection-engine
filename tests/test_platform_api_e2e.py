"""End-to-end acceptance + API security tests (real PostgreSQL, real detector).

This is the Milestone C primary acceptance test. It drives the complete workflow
through the real FastAPI endpoints against a real PostgreSQL database and the
real PatientAccessDetector, using clearly-labeled SYNTHETIC security events and
MIMIC-derived clinical context.

Requires: reachable PostgreSQL and the ATT&CK core (attack_v19_core). Skips with
an explicit reason otherwise.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

TEST_DB_URL = os.environ.get(
    "AEGIS_TEST_DATABASE_URL", "postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
)
os.environ.setdefault("AEGIS_DATABASE_URL", TEST_DB_URL)
os.environ.setdefault("AEGIS_JWT_SECRET", "e2e-test-secret-stable")


def _deps_available() -> bool:
    try:
        import fastapi  # noqa: F401
        from sqlalchemy import text

        import attack_v19_core  # noqa: F401
        from detection_engine.platform import db as _db

        engine = _db.make_engine(TEST_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _deps_available(), reason="requires PostgreSQL + fastapi + attack_v19_core"
)


@pytest.fixture()
def app_client():
    from fastapi.testclient import TestClient

    from detection_engine.platform import db as _db
    from detection_engine.platform.bootstrap import build_app, seed_user
    from detection_engine.healthcare.context import ActorProfile, ClinicalContext

    engine = _db.make_engine(TEST_DB_URL)
    _db.Base.metadata.drop_all(engine)
    _db.Base.metadata.create_all(engine)

    # Seed users in two organizations.
    S = _db.make_session_factory(engine)
    s = S()
    seed_user(s, user_id="u-analyst-a", username="analyst_a", password="pw-a",
              role="security_analyst", organization_id="org-a")
    seed_user(s, user_id="u-analyst-b", username="analyst_b", password="pw-b",
              role="security_analyst", organization_id="org-b")
    seed_user(s, user_id="u-auditor-a", username="auditor_a", password="pw-aud",
              role="read_only_auditor", organization_id="org-a")
    s.close()

    # Clinical context: a provider with a small panel (authorization) so bulk
    # access to OTHER patients is anomalous.
    ctx = ClinicalContext(actors={
        "clin-7": ActorProfile(
            actor_id="clin-7", actor_type="clinician", role="attending",
            department="cardiology", assigned_patients={"pt-0001", "pt-0002"},
            shift=(7, 19),
        )
    })
    app = build_app(clinical_context=ctx)
    client = TestClient(app)
    yield client, engine
    engine.dispose()


def _token(client, username, password):
    r = client.post("/api/v1/auth/token", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _suspicious_batch():
    """A single identity bulk-reading many UNASSIGNED patients -> anomaly."""
    base = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    return [
        {
            "actor_id": "clin-7",
            "patient_ref": f"pt-9{i:03d}",
            "resource_id": f"res-9{i:03d}-enc",
            "action": "read",
            "outcome": "success",
            "timestamp": (base + timedelta(seconds=10 * i)).isoformat(),
            "source_host": "ws-1",
            "data_origin": "synthetic",
        }
        for i in range(40)
    ]


def _benign_batch():
    """The provider reads only their assigned patients -> no HIGH/CRITICAL."""
    base = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    return [
        {
            "actor_id": "clin-7", "patient_ref": p, "resource_id": f"res-{p}-enc",
            "action": "read", "outcome": "success",
            "timestamp": (base + timedelta(minutes=i)).isoformat(),
            "data_origin": "synthetic",
        }
        for i, p in enumerate(["pt-0001", "pt-0002"])
    ]


class TestEndToEndAcceptance:
    def test_full_investigation_workflow(self, app_client):
        client, engine = app_client
        token = _token(client, "analyst_a", "pw-a")

        # 1-5. Ingest -> detect -> correlate -> persist (one API call)
        r = client.post("/api/v1/events", json={"events": _suspicious_batch()}, headers=_auth(token))
        assert r.status_code == 202, r.text
        result = r.json()
        assert result["accepted"] == 40
        assert result["finding_ids"], "detector should produce findings"
        assert result["incident_ids"], "correlation should create an incident"
        incident_id = result["incident_ids"][0]

        # 6. Retrieve incident via real API
        r = client.get(f"/api/v1/incidents/{incident_id}", headers=_auth(token))
        assert r.status_code == 200
        inc = r.json()
        assert inc["status"] == "NEW"
        assert inc["severity"] in {"HIGH", "CRITICAL", "MEDIUM"}

        # 7. Evidence explains what/why
        ev = client.get(f"/api/v1/incidents/{incident_id}/evidence", headers=_auth(token)).json()
        assert ev["findings"]
        assert any("HC-ACCESS" in f["rule_id"] for f in ev["findings"])
        # No clinical record content leaked into evidence
        for f in ev["findings"]:
            assert "patient_name" not in f["evidence"]

        # 8. Authenticated analyst investigates: assign -> note -> status -> disposition
        assert client.post(f"/api/v1/incidents/{incident_id}/assign",
                           json={"analyst_id": "analyst_a"}, headers=_auth(token)).status_code == 200
        assert client.post(f"/api/v1/incidents/{incident_id}/notes",
                           json={"note": "Reviewed access pattern; bulk reads of unassigned patients."},
                           headers=_auth(token)).status_code == 200
        assert client.patch(f"/api/v1/incidents/{incident_id}",
                           json={"status": "INVESTIGATING"}, headers=_auth(token)).status_code == 200
        assert client.post(f"/api/v1/incidents/{incident_id}/disposition",
                           json={"disposition": "true_positive", "summary": "Confirmed anomalous bulk access."},
                           headers=_auth(token)).status_code == 200

        # 9. Resolve/close
        assert client.patch(f"/api/v1/incidents/{incident_id}",
                           json={"status": "RESOLVED"}, headers=_auth(token)).status_code == 200
        assert client.post(f"/api/v1/incidents/{incident_id}/close",
                           json={"reason": "remediated"}, headers=_auth(token)).status_code == 200

        # Timeline distinguishes events, findings, and analyst actions
        tl = client.get(f"/api/v1/incidents/{incident_id}/timeline", headers=_auth(token)).json()["timeline"]
        kinds = {t["kind"] for t in tl}
        assert {"finding", "analyst_action"}.issubset(kinds)

        # Audit history has the full action sequence
        hist = client.get(f"/api/v1/incidents/{incident_id}/history", headers=_auth(token)).json()["actions"]
        action_types = [a["action_type"] for a in hist]
        assert "assign" in action_types
        assert "add_note" in action_types
        assert "status_change" in action_types
        assert "disposition" in action_types
        assert "close" in action_types

        # 10. RESTART: dispose engine, build a fresh app, verify persistence
        engine.dispose()
        from fastapi.testclient import TestClient
        from detection_engine.platform.bootstrap import build_app

        client2 = TestClient(build_app())
        token2 = _token(client2, "analyst_a", "pw-a")
        r = client2.get(f"/api/v1/incidents/{incident_id}", headers=_auth(token2))
        assert r.status_code == 200
        assert r.json()["status"] == "CLOSED"
        assert r.json()["close_reason"] == "remediated"
        hist2 = client2.get(f"/api/v1/incidents/{incident_id}/history", headers=_auth(token2)).json()["actions"]
        assert len(hist2) == len(hist)  # audit trail survived restart

    def test_benign_access_no_high_incident(self, app_client):
        client, _ = app_client
        token = _token(client, "analyst_a", "pw-a")
        r = client.post("/api/v1/events", json={"events": _benign_batch()}, headers=_auth(token))
        assert r.status_code == 202
        # Any incident created must not be HIGH/CRITICAL
        incidents = client.get("/api/v1/incidents", headers=_auth(token)).json()["items"]
        assert not [i for i in incidents if i["severity"] in {"HIGH", "CRITICAL"}]


class TestSecurityBoundaries:
    def test_unauthenticated_rejected(self, app_client):
        client, _ = app_client
        assert client.get("/api/v1/incidents").status_code == 401
        assert client.post("/api/v1/events", json={"events": []}).status_code == 401

    def test_cross_org_incident_access_blocked(self, app_client):
        client, _ = app_client
        token_a = _token(client, "analyst_a", "pw-a")
        token_b = _token(client, "analyst_b", "pw-b")
        # org-a creates an incident
        client.post("/api/v1/events", json={"events": _suspicious_batch()}, headers=_auth(token_a))
        inc_id = client.get("/api/v1/incidents", headers=_auth(token_a)).json()["items"][0]["incident_id"]
        # org-b cannot read it (404, not 403, to avoid leaking existence)
        assert client.get(f"/api/v1/incidents/{inc_id}", headers=_auth(token_b)).status_code == 404
        assert client.get(f"/api/v1/incidents/{inc_id}/evidence", headers=_auth(token_b)).status_code == 404
        # org-b's incident list is empty
        assert client.get("/api/v1/incidents", headers=_auth(token_b)).json()["total"] == 0

    def test_auditor_cannot_modify(self, app_client):
        client, _ = app_client
        analyst = _token(client, "analyst_a", "pw-a")
        client.post("/api/v1/events", json={"events": _suspicious_batch()}, headers=_auth(analyst))
        inc_id = client.get("/api/v1/incidents", headers=_auth(analyst)).json()["items"][0]["incident_id"]
        auditor = _token(client, "auditor_a", "pw-aud")
        # Auditor can read
        assert client.get(f"/api/v1/incidents/{inc_id}", headers=_auth(auditor)).status_code == 200
        # Auditor cannot write
        assert client.post(f"/api/v1/incidents/{inc_id}/notes", json={"note": "x"}, headers=_auth(auditor)).status_code == 403
        assert client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "INVESTIGATING"}, headers=_auth(auditor)).status_code == 403

    def test_duplicate_events_deduped(self, app_client):
        client, _ = app_client
        token = _token(client, "analyst_a", "pw-a")
        batch = [{
            "actor_id": "clin-7", "patient_ref": "pt-0001", "resource_id": "res-x",
            "action": "read", "outcome": "success", "source_event_id": "DUP-1",
            "timestamp": "2026-10-27T10:00:00+00:00", "data_origin": "synthetic",
        }]
        r1 = client.post("/api/v1/events", json={"events": batch}, headers=_auth(token)).json()
        r2 = client.post("/api/v1/events", json={"events": batch}, headers=_auth(token)).json()
        assert r1["accepted"] == 1
        assert r2["accepted"] == 0 and r2["duplicates"] == 1

    def test_invalid_event_rejected(self, app_client):
        client, _ = app_client
        token = _token(client, "analyst_a", "pw-a")
        # Missing required 'timestamp' -> rejected, counted, not crashing
        r = client.post("/api/v1/events", json={"events": [{"actor_id": "x"}]}, headers=_auth(token))
        assert r.status_code == 202
        assert r.json()["rejected"] == 1

    def test_invalid_status_transition_409(self, app_client):
        client, _ = app_client
        token = _token(client, "analyst_a", "pw-a")
        client.post("/api/v1/events", json={"events": _suspicious_batch()}, headers=_auth(token))
        inc_id = client.get("/api/v1/incidents", headers=_auth(token)).json()["items"][0]["incident_id"]
        # NEW -> RESOLVED is not a legal direct transition
        r = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "RESOLVED"}, headers=_auth(token))
        assert r.status_code == 409
