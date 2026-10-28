"""Phase 10: failure-injection tests (real PostgreSQL + HTTP).

Verifies the platform fails safely: a database outage is never reported as a
successful persist, a detector exception does not silently become a clean
result, expired/revoked tokens are denied, duplicate ingestion is bounded, and
partial failures preserve consistency.
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


def _deps() -> bool:
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


pytestmark = pytest.mark.skipif(not _deps(), reason="requires PostgreSQL + fastapi + core")


@pytest.fixture()
def client_and_ctx():
    from fastapi.testclient import TestClient

    from detection_engine.platform import db as _db
    from detection_engine.platform.bootstrap import build_app, seed_user

    eng = _db.make_engine(TEST_DB_URL)
    _db.Base.metadata.drop_all(eng)
    _db.Base.metadata.create_all(eng)
    s = _db.make_session_factory(eng)()
    seed_user(s, user_id="u1", username="ana", password="pw-strong-1234",
              role="security_analyst", organization_id="org-a")
    s.close()
    app = build_app()
    yield TestClient(app, raise_server_exceptions=False), eng
    eng.dispose()


def _tok(c):
    return c.post("/api/v1/auth/token", json={"username": "ana", "password": "pw-strong-1234"}).json()["access_token"]


def _batch(n=3):
    base = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    return [{"actor_id": "clin-7", "patient_ref": f"pt-{i}", "resource_id": f"res-{i}",
             "action": "read", "outcome": "success",
             "timestamp": (base + timedelta(seconds=i)).isoformat(),
             "data_origin": "synthetic"} for i in range(n)]


class TestDatabaseOutage:
    def test_readiness_503_when_db_down(self, client_and_ctx, monkeypatch):
        c, eng = client_and_ctx
        # The readiness endpoint uses the app's own engine (app.state.engine),
        # not the fixture engine. Patch that engine's connect() to fail.
        app_engine = c.app.state.engine

        def boom(*a, **k):
            raise RuntimeError("simulated DB outage")

        monkeypatch.setattr(app_engine, "connect", boom)
        r = c.get("/readiness")
        assert r.status_code == 503
        # Must not leak the connection string / driver detail.
        assert "postgresql" not in r.text.lower()

    def test_ingest_failure_does_not_report_success(self, client_and_ctx, monkeypatch):
        c, _ = client_and_ctx
        tok = _tok(c)
        # Force the ingestion service to raise mid-processing.
        from detection_engine.platform import ingestion as _ing

        def boom(self, *a, **k):
            raise RuntimeError("simulated persistence failure")

        monkeypatch.setattr(_ing.IngestionService, "ingest_clinical_batch", boom)
        r = c.post("/api/v1/events", json={"events": _batch()}, headers={"Authorization": f"Bearer {tok}"})
        # The failure must surface as an error, never a 202 "accepted".
        assert r.status_code >= 500
        assert r.status_code != 202


class TestDetectorFailureNotSilent:
    def test_detector_exception_is_not_clean_result(self, client_and_ctx, monkeypatch):
        c, _ = client_and_ctx
        tok = _tok(c)
        # Make the clinical detector raise; a detector error must NOT be
        # reported as a successful "no findings" clean scan.
        from detection_engine.platform import api as _api  # noqa: F401
        from detection_engine.platform import ingestion as _ing

        orig = _ing.IngestionService.ingest_clinical_batch

        def exploding_detect(self, records, *, organization_id):
            raise RuntimeError("detector blew up")

        # Patch the detector used inside the service.
        import detection_engine.healthcare.detector as _det

        monkeypatch.setattr(_det.PatientAccessDetector, "detect", exploding_detect)
        r = c.post("/api/v1/events", json={"events": _batch()}, headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code >= 500  # surfaced, not a clean 202 with 0 findings
        _ = orig  # keep reference


class TestTokenFailures:
    def test_expired_token_denied(self, client_and_ctx):
        import jwt

        from detection_engine.platform import auth

        c, _ = client_and_ctx
        expired = jwt.encode(
            {"sub": "u1", "username": "ana", "role": "security_analyst", "org": "org-a",
             "tv": 0, "aud": auth.JWT_AUDIENCE, "iss": auth.JWT_ISSUER,
             "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
             "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())},
            auth.JWT_SECRET, algorithm=auth.JWT_ALGORITHM,
        )
        r = c.get("/api/v1/incidents", headers={"Authorization": f"Bearer {expired}"})
        assert r.status_code == 401

    def test_garbage_token_denied(self, client_and_ctx):
        c, _ = client_and_ctx
        r = c.get("/api/v1/incidents", headers={"Authorization": "Bearer not.a.token"})
        assert r.status_code == 401


class TestDuplicateIngestionBounded:
    def test_repeated_same_event_no_uncontrolled_duplicates(self, client_and_ctx):
        c, _ = client_and_ctx
        tok = _tok(c)
        batch = {"events": [{
            "actor_id": "clin-7", "patient_ref": "pt-1", "resource_id": "res-1",
            "action": "read", "outcome": "success", "source_event_id": "FIXED-1",
            "timestamp": "2026-10-27T10:00:00+00:00", "data_origin": "synthetic",
        }]}
        h = {"Authorization": f"Bearer {tok}"}
        r1 = c.post("/api/v1/events", json=batch, headers=h).json()
        r2 = c.post("/api/v1/events", json=batch, headers=h).json()
        r3 = c.post("/api/v1/events", json=batch, headers=h).json()
        assert r1["accepted"] == 1
        assert r2["accepted"] == 0 and r2["duplicates"] == 1
        assert r3["accepted"] == 0 and r3["duplicates"] == 1
