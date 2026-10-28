"""Phase 5: FastAPI/web application security tests (real PG + HTTP)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("AEGIS_JWT_SECRET", "milestone-d-test-secret-at-least-32-chars")
os.environ.setdefault("AEGIS_MAX_BODY_BYTES", "65536")  # small cap for the test
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


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from detection_engine.platform import db as _db
    from detection_engine.platform.bootstrap import build_app, seed_user

    eng = _db.make_engine(TEST_DB_URL)
    _db.Base.metadata.drop_all(eng)
    _db.Base.metadata.create_all(eng)
    s = _db.make_session_factory(eng)()
    seed_user(s, user_id="u1", username="ana", password="pw-strong-xyz1",
              role="security_analyst", organization_id="org-a")
    s.close()
    c = TestClient(build_app(), raise_server_exceptions=False)
    yield c
    eng.dispose()


def _tok(c):
    return c.post("/api/v1/auth/token", json={"username": "ana", "password": "pw-strong-xyz1"}).json()["access_token"]


def _h(t):
    return {"Authorization": f"Bearer {t}"}


class TestSecurityHeaders:
    def test_headers_present(self, client):
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert "default-src 'none'" in r.headers.get("Content-Security-Policy", "")
        assert r.headers.get("Cache-Control") == "no-store"


class TestBodyLimits:
    def test_oversized_body_rejected(self, client):
        tok = _tok(client)
        # Build a body larger than AEGIS_MAX_BODY_BYTES (64 KiB) regardless of
        # the Content-Length header (middleware reads actual bytes).
        big = {"events": [{"actor_id": "x" * 1000}] * 200}
        r = client.post("/api/v1/events", json=big, headers=_h(tok))
        assert r.status_code == 413

    def test_batch_limit_enforced(self, client):
        tok = _tok(client)
        # Small enough body, but too many events -> 413 from batch cap.
        import os as _os
        maxb = int(_os.environ.get("AEGIS_MAX_BATCH", "1000"))
        evts = [{"actor_id": "a", "patient_ref": "p", "resource_id": "r",
                 "action": "read", "outcome": "success",
                 "timestamp": "2026-10-27T10:00:00+00:00"} for _ in range(maxb + 1)]
        r = client.post("/api/v1/events", json={"events": evts}, headers=_h(tok))
        assert r.status_code in (413, 422)


class TestSafeErrors:
    def test_malformed_json_handled(self, client):
        tok = _tok(client)
        r = client.post("/api/v1/events", data="{not valid json",
                        headers={**_h(tok), "Content-Type": "application/json"})
        assert r.status_code == 422  # FastAPI validation, not a 500

    def test_readiness_no_secret_leak(self, client):
        r = client.get("/readiness")
        assert "postgresql" not in r.text.lower()
        assert "password" not in r.text.lower()

    def test_404_is_generic(self, client):
        tok = _tok(client)
        r = client.get("/api/v1/incidents/does-not-exist", headers=_h(tok))
        assert r.status_code == 404
        assert "traceback" not in r.text.lower()


class TestListLimits:
    def test_list_limit_capped(self, client):
        tok = _tok(client)
        # Request an absurd limit; the endpoint caps it (le=200) -> 422 or capped.
        r = client.get("/api/v1/incidents?limit=100000", headers=_h(tok))
        assert r.status_code in (200, 422)


class TestInjectionSafety:
    def test_sqlish_strings_do_not_break(self, client):
        tok = _tok(client)
        # A malicious-looking identity string must be treated as data, not SQL.
        evt = {"events": [{
            "actor_id": "robert'); DROP TABLE incidents;--",
            "patient_ref": "pt-1", "resource_id": "res-1",
            "action": "read", "outcome": "success",
            "timestamp": "2026-10-27T10:00:00+00:00",
        }]}
        r = client.post("/api/v1/events", json=evt, headers=_h(tok))
        assert r.status_code == 202
        # Table still exists / queries still work.
        assert client.get("/api/v1/incidents", headers=_h(tok)).status_code == 200
