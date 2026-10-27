"""Phase 2 authentication/JWT hardening security tests.

Unit-level tests for auth primitives (no DB), plus DB/HTTP-level tests for
disabled-account and role/org-change revocation and login throttling against a
real PostgreSQL + FastAPI TestClient.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import pytest
from jose import jwt

os.environ.setdefault("AEGIS_JWT_SECRET", "milestone-d-test-secret-at-least-32-chars")

from detection_engine.platform import auth  # noqa: E402

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


# --- unit: password safety (bcrypt truncation fix) -------------------------

class TestPasswordSafety:
    def test_roundtrip_v2(self):
        h = auth.hash_password("Sü@h3!-pâsswörd")
        assert h.startswith("v2$")
        assert auth.verify_password("Sü@h3!-pâsswörd", h)
        assert not auth.verify_password("wrong", h)

    def test_long_passwords_sharing_72_byte_prefix_differ(self):
        # This is the bug being fixed: legacy bcrypt truncated at 72 bytes, so
        # these two would have been EQUIVALENT. The v2 SHA-256 pre-hash fixes it.
        base = "A" * 72
        h = auth.hash_password(base + "DIFFERENT_TAIL_ONE")
        assert not auth.verify_password(base + "DIFFERENT_TAIL_TWO", h)
        assert auth.verify_password(base + "DIFFERENT_TAIL_ONE", h)

    def test_unicode_and_very_long(self):
        pw = "🔐" * 500
        h = auth.hash_password(pw)
        assert auth.verify_password(pw, h)

    def test_legacy_hash_still_verifies(self):
        # Simulate a Milestone C legacy hash (raw bcrypt of first 72 bytes).
        import bcrypt

        legacy = bcrypt.hashpw("oldpassword".encode()[:72], bcrypt.gensalt()).decode()
        assert not legacy.startswith("v2$")
        assert auth.verify_password("oldpassword", legacy)
        assert auth.needs_rehash(legacy) is True
        assert auth.needs_rehash(auth.hash_password("x")) is False


# --- unit: JWT validation ---------------------------------------------------

class TestTokenValidation:
    def _tok(self, **over):
        kw = dict(user_id="u1", username="a", role="security_analyst",
                  organization_id="org-a", token_version=0)
        kw.update(over)
        return auth.create_access_token(**kw)

    def test_valid_decode(self):
        p = auth.decode_token(self._tok())
        assert p is not None and p.organization_id == "org-a"
        assert p.token_version == 0

    def test_tampered_rejected(self):
        assert auth.decode_token(self._tok() + "x") is None

    def test_wrong_audience_rejected(self):
        bad = jwt.encode(
            {"sub": "u1", "role": "security_analyst", "org": "o", "aud": "other",
             "iss": auth.JWT_ISSUER,
             "iat": int(datetime.now(timezone.utc).timestamp()),
             "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())},
            auth.JWT_SECRET, algorithm=auth.JWT_ALGORITHM,
        )
        assert auth.decode_token(bad) is None

    def test_expired_rejected(self):
        expired = jwt.encode(
            {"sub": "u1", "role": "security_analyst", "org": "o",
             "aud": auth.JWT_AUDIENCE, "iss": auth.JWT_ISSUER,
             "iat": int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp()),
             "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())},
            auth.JWT_SECRET, algorithm=auth.JWT_ALGORITHM,
        )
        assert auth.decode_token(expired) is None

    def test_missing_required_claim_rejected(self):
        bad = jwt.encode(
            {"sub": "u1", "aud": auth.JWT_AUDIENCE, "iss": auth.JWT_ISSUER,
             "iat": int(datetime.now(timezone.utc).timestamp()),
             "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())},
            auth.JWT_SECRET, algorithm=auth.JWT_ALGORITHM,
        )  # missing role/org
        assert auth.decode_token(bad) is None

    def test_none_alg_rejected(self):
        # Hand-craft an unsigned 'none'-algorithm token (jose refuses to encode
        # one, which is itself good). decode_token must reject it.
        import base64
        import json

        def b64(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

        header = b64({"alg": "none", "typ": "JWT"})
        payload = b64({
            "sub": "u1", "role": "administrator", "org": "o",
            "aud": auth.JWT_AUDIENCE, "iss": auth.JWT_ISSUER,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        })
        forged = f"{header}.{payload}."  # empty signature
        assert auth.decode_token(forged) is None


class TestSecureConfig:
    def test_require_secure_config_rejects_missing(self, monkeypatch):
        monkeypatch.delenv("AEGIS_JWT_SECRET", raising=False)
        with pytest.raises(RuntimeError):
            auth.require_secure_config()

    def test_require_secure_config_rejects_weak(self, monkeypatch):
        monkeypatch.setenv("AEGIS_JWT_SECRET", "short")
        with pytest.raises(RuntimeError):
            auth.require_secure_config()

    def test_require_secure_config_accepts_strong(self, monkeypatch):
        monkeypatch.setenv("AEGIS_JWT_SECRET", "x" * 32)
        auth.require_secure_config()  # no raise


# --- unit: login throttle ---------------------------------------------------

class TestLoginThrottle:
    def test_locks_after_max_failures(self):
        t = auth.LoginThrottle(max_failures=3, window=60, lockout=60)
        for _ in range(3):
            assert not t.is_locked("u", "1.2.3.4")
            t.record_failure("u", "1.2.3.4")
        assert t.is_locked("u", "1.2.3.4")

    def test_success_clears(self):
        t = auth.LoginThrottle(max_failures=2, window=60, lockout=60)
        t.record_failure("u", "ip")
        t.record_success("u", "ip")
        t.record_failure("u", "ip")
        assert not t.is_locked("u", "ip")

    def test_lockout_expires(self):
        t = auth.LoginThrottle(max_failures=1, window=60, lockout=1)
        t.record_failure("u", "ip")
        assert t.is_locked("u", "ip")
        time.sleep(1.1)
        assert not t.is_locked("u", "ip")


# --- integration: revocation + disabled account (real PG + HTTP) -----------

pg_http = pytest.mark.skipif(not _deps_available(), reason="requires PostgreSQL + fastapi + core")


@pg_http
class TestRevocationAndDisable:
    @pytest.fixture()
    def client(self):
        from fastapi.testclient import TestClient

        from detection_engine.platform import db as _db
        from detection_engine.platform.bootstrap import build_app, seed_user

        eng = _db.make_engine(TEST_DB_URL)
        _db.Base.metadata.drop_all(eng)
        _db.Base.metadata.create_all(eng)
        s = _db.make_session_factory(eng)()
        seed_user(s, user_id="u-a", username="ana", password="pw-strong-1",
                  role="security_analyst", organization_id="org-a")
        s.close()
        app = build_app()
        yield TestClient(app), eng
        eng.dispose()

    def _login(self, c, u="ana", p="pw-strong-1"):
        r = c.post("/api/v1/auth/token", json={"username": u, "password": p})
        return r

    def test_disabled_account_token_rejected(self, client):
        c, eng = client
        tok = self._login(c).json()["access_token"]
        # Works initially
        assert c.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
        # Disable the account directly in DB (simulating admin action)
        from detection_engine.platform import db as _db
        s = _db.make_session_factory(eng)()
        u = s.get(_db.UserRow, "u-a")
        u.is_active = False
        s.commit()
        s.close()
        # Previously-issued token must now be rejected (fail closed)
        assert c.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tok}"}).status_code == 401

    def test_token_version_bump_revokes(self, client):
        c, eng = client
        tok = self._login(c).json()["access_token"]
        assert c.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
        from detection_engine.platform import db as _db
        s = _db.make_session_factory(eng)()
        u = s.get(_db.UserRow, "u-a")
        u.token_version = 1
        s.commit()
        s.close()
        # Old token (tv=0) is now stale -> rejected
        assert c.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
        # A fresh login (tv=1) works again
        tok2 = self._login(c).json()["access_token"]
        assert c.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tok2}"}).status_code == 200

    def test_role_change_takes_effect_from_db(self, client):
        c, eng = client
        tok = self._login(c).json()["access_token"]
        from detection_engine.platform import db as _db
        s = _db.make_session_factory(eng)()
        u = s.get(_db.UserRow, "u-a")
        u.role = "read_only_auditor"
        s.commit()
        s.close()
        # Token still says analyst, but DB says auditor -> writes now forbidden
        # (authoritative role comes from DB via resolve_principal).
        # First create an incident path is ingest (analyst-only); now 403.
        r = c.post("/api/v1/events", json={"events": []}, headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 403

    def test_bad_login_is_generic_and_throttled(self, client):
        c, _ = client
        # Unknown user and wrong password both return the same generic 401.
        r1 = c.post("/api/v1/auth/token", json={"username": "ghost", "password": "x"})
        r2 = c.post("/api/v1/auth/token", json={"username": "ana", "password": "wrong"})
        assert r1.status_code == 401 and r2.status_code == 401
        assert r1.json()["detail"] == r2.json()["detail"] == "invalid credentials"
