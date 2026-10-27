"""Phase 3: RBAC + multi-tenant isolation adversarial tests (real PG + HTTP).

Exercises EVERY incident endpoint with a foreign-organization token and with an
under-privileged role, asserting that cross-organization access is impossible
(404, no existence leak) and that writes are role-gated. Organization is always
derived server-side from the token, never from client input.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("AEGIS_JWT_SECRET", "milestone-d-test-secret-at-least-32-chars")
TEST_DB_URL = os.environ.get(
    "AEGIS_TEST_DATABASE_URL", "postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
)
os.environ.setdefault("AEGIS_DATABASE_URL", TEST_DB_URL)


def _deps_available() -> bool:
    try:
        import fastapi  # noqa: F401
        from sqlalchemy import text

        import attack_v19_core  # noqa: F401
        from detection_engine.platform import db as _db

        eng = _db.make_engine(TEST_DB_URL)
        with eng.connect() as c:
            c.execute(text("SELECT 1"))
        eng.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _deps_available(), reason="requires PostgreSQL + fastapi + core")


def _suspicious_batch(actor="clin-7"):
    base = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    return [
        {
            "actor_id": actor, "patient_ref": f"pt-9{i:03d}", "resource_id": f"res-9{i:03d}",
            "action": "read", "outcome": "success",
            "timestamp": (base + timedelta(seconds=10 * i)).isoformat(),
            "data_origin": "synthetic",
        }
        for i in range(40)
    ]


@pytest.fixture()
def two_org_client():
    from fastapi.testclient import TestClient

    from detection_engine.platform import db as _db
    from detection_engine.platform.bootstrap import build_app, seed_user

    eng = _db.make_engine(TEST_DB_URL)
    _db.Base.metadata.drop_all(eng)
    _db.Base.metadata.create_all(eng)
    s = _db.make_session_factory(eng)()
    seed_user(s, user_id="a-a", username="ana_a", password="pw-strong-aaaa",
              role="security_analyst", organization_id="org-a")
    seed_user(s, user_id="a-b", username="ana_b", password="pw-strong-bbbb",
              role="security_analyst", organization_id="org-b")
    seed_user(s, user_id="aud-a", username="aud_a", password="pw-strong-cccc",
              role="read_only_auditor", organization_id="org-a")
    s.close()
    c = TestClient(build_app())
    yield c, eng
    eng.dispose()


def _tok(c, u, p):
    return c.post("/api/v1/auth/token", json={"username": u, "password": p}).json()["access_token"]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


def _make_incident(c, tok):
    c.post("/api/v1/events", json={"events": _suspicious_batch()}, headers=_h(tok))
    return c.get("/api/v1/incidents", headers=_h(tok)).json()["items"][0]["incident_id"]


class TestCrossOrgIsolationEveryEndpoint:
    """Org-A creates an incident; Org-B must be blocked on EVERY path."""

    @pytest.fixture()
    def setup(self, two_org_client):
        c, eng = two_org_client
        tok_a = _tok(c, "ana_a", "pw-strong-aaaa")
        tok_b = _tok(c, "ana_b", "pw-strong-bbbb")
        inc = _make_incident(c, tok_a)
        return c, tok_a, tok_b, inc

    def test_get_incident_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        assert c.get(f"/api/v1/incidents/{inc}", headers=_h(tok_b)).status_code == 404

    def test_evidence_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        assert c.get(f"/api/v1/incidents/{inc}/evidence", headers=_h(tok_b)).status_code == 404

    def test_timeline_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        assert c.get(f"/api/v1/incidents/{inc}/timeline", headers=_h(tok_b)).status_code == 404

    def test_history_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        assert c.get(f"/api/v1/incidents/{inc}/history", headers=_h(tok_b)).status_code == 404

    def test_export_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        assert c.get(f"/api/v1/incidents/{inc}/export", headers=_h(tok_b)).status_code == 404

    def test_assign_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        r = c.post(f"/api/v1/incidents/{inc}/assign", json={"analyst_id": "x"}, headers=_h(tok_b))
        assert r.status_code == 404

    def test_notes_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        r = c.post(f"/api/v1/incidents/{inc}/notes", json={"note": "intrusion"}, headers=_h(tok_b))
        assert r.status_code == 404

    def test_status_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        r = c.patch(f"/api/v1/incidents/{inc}", json={"status": "INVESTIGATING"}, headers=_h(tok_b))
        assert r.status_code == 404

    def test_disposition_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        r = c.post(f"/api/v1/incidents/{inc}/disposition", json={"disposition": "x"}, headers=_h(tok_b))
        assert r.status_code == 404

    def test_close_cross_org_404(self, setup):
        c, _, tok_b, inc = setup
        r = c.post(f"/api/v1/incidents/{inc}/close", json={"reason": "x"}, headers=_h(tok_b))
        assert r.status_code == 404

    def test_list_excludes_other_org(self, setup):
        c, _, tok_b, _ = setup
        assert c.get("/api/v1/incidents", headers=_h(tok_b)).json()["total"] == 0

    def test_org_b_cannot_affect_org_a_incident_state(self, setup):
        c, tok_a, tok_b, inc = setup
        # Org-B's blocked attempts must not change Org-A's incident.
        c.patch(f"/api/v1/incidents/{inc}", json={"status": "INVESTIGATING"}, headers=_h(tok_b))
        assert c.get(f"/api/v1/incidents/{inc}", headers=_h(tok_a)).json()["status"] == "NEW"


class TestRoleEnforcementEveryWriteEndpoint:
    """Read-only auditor in org-A must be blocked on EVERY write path (403)."""

    @pytest.fixture()
    def setup(self, two_org_client):
        c, eng = two_org_client
        tok_a = _tok(c, "ana_a", "pw-strong-aaaa")
        inc = _make_incident(c, tok_a)
        tok_aud = _tok(c, "aud_a", "pw-strong-cccc")
        return c, tok_aud, inc

    def test_auditor_cannot_ingest(self, setup):
        c, tok_aud, _ = setup
        assert c.post("/api/v1/events", json={"events": []}, headers=_h(tok_aud)).status_code == 403

    def test_auditor_cannot_assign(self, setup):
        c, tok_aud, inc = setup
        assert c.post(f"/api/v1/incidents/{inc}/assign", json={"analyst_id": "x"}, headers=_h(tok_aud)).status_code == 403

    def test_auditor_cannot_note(self, setup):
        c, tok_aud, inc = setup
        assert c.post(f"/api/v1/incidents/{inc}/notes", json={"note": "x"}, headers=_h(tok_aud)).status_code == 403

    def test_auditor_cannot_change_status(self, setup):
        c, tok_aud, inc = setup
        assert c.patch(f"/api/v1/incidents/{inc}", json={"status": "INVESTIGATING"}, headers=_h(tok_aud)).status_code == 403

    def test_auditor_cannot_disposition(self, setup):
        c, tok_aud, inc = setup
        assert c.post(f"/api/v1/incidents/{inc}/disposition", json={"disposition": "x"}, headers=_h(tok_aud)).status_code == 403

    def test_auditor_cannot_close(self, setup):
        c, tok_aud, inc = setup
        assert c.post(f"/api/v1/incidents/{inc}/close", json={"reason": "x"}, headers=_h(tok_aud)).status_code == 403

    def test_auditor_can_read(self, setup):
        c, tok_aud, inc = setup
        assert c.get(f"/api/v1/incidents/{inc}", headers=_h(tok_aud)).status_code == 200
        assert c.get(f"/api/v1/incidents/{inc}/evidence", headers=_h(tok_aud)).status_code == 200


class TestServerSideOrgBinding:
    def test_client_cannot_override_org_via_event_payload(self, two_org_client):
        c, eng = two_org_client
        tok_a = _tok(c, "ana_a", "pw-strong-aaaa")
        # Attempt to inject organization_id for org-b in the event payload.
        evt = _suspicious_batch()
        for e in evt:
            e["organization_id"] = "org-b"
        c.post("/api/v1/events", json={"events": evt}, headers=_h(tok_a))
        # The incident must belong to org-a (token), not the injected org-b.
        tok_b = _tok(c, "ana_b", "pw-strong-bbbb")
        assert c.get("/api/v1/incidents", headers=_h(tok_b)).json()["total"] == 0
        assert c.get("/api/v1/incidents", headers=_h(tok_a)).json()["total"] >= 1

    def test_db_scoping_foreign_incident_id_substitution(self, two_org_client):
        # Directly substitute a foreign incident_id: repository is org-scoped.
        from detection_engine.platform import db as _db
        from detection_engine.platform.repository import Repository

        c, eng = two_org_client
        tok_a = _tok(c, "ana_a", "pw-strong-aaaa")
        inc = _make_incident(c, tok_a)
        s = _db.make_session_factory(eng)()
        repo = Repository(s)
        assert repo.get_incident(inc, "org-a") is not None
        assert repo.get_incident(inc, "org-b") is None  # scoping blocks substitution
        s.close()
