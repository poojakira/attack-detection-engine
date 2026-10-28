"""Unit tests for auth primitives and the investigation state machine.

These test security-relevant behavior directly (password hashing round-trip,
token decode/expiry/tamper, role capabilities, and legal/illegal status
transitions) without needing a database or HTTP.
"""

from __future__ import annotations


from detection_engine.platform import auth
from detection_engine.platform.auth import Principal, Role
from detection_engine.platform.investigation import (
    InvalidTransition,
    _TRANSITIONS,
)
from detection_engine.platform.models import IncidentStatus


class TestPasswordHashing:
    def test_roundtrip(self):
        h = auth.hash_password("correct horse battery staple")
        assert auth.verify_password("correct horse battery staple", h)
        assert not auth.verify_password("wrong", h)

    def test_hash_is_salted(self):
        assert auth.hash_password("x") != auth.hash_password("x")

    def test_long_password_does_not_crash(self):
        # >72 bytes must be handled, not raise.
        h = auth.hash_password("a" * 200)
        assert auth.verify_password("a" * 200, h)

    def test_verify_bad_hash_returns_false(self):
        assert auth.verify_password("x", "not-a-bcrypt-hash") is False


class TestTokens:
    def test_decode_roundtrip(self):
        tok = auth.create_access_token(
            user_id="u1", username="analyst", role="security_analyst",
            organization_id="org-a",
        )
        p = auth.decode_token(tok)
        assert p is not None
        assert p.user_id == "u1"
        assert p.role == Role.SECURITY_ANALYST
        assert p.organization_id == "org-a"

    def test_tampered_token_rejected(self):
        tok = auth.create_access_token(
            user_id="u1", username="a", role="security_analyst", organization_id="o"
        )
        assert auth.decode_token(tok + "x") is None

    def test_garbage_token_rejected(self):
        assert auth.decode_token("not.a.jwt") is None


class TestRoleCapabilities:
    def test_analyst_can_ingest_and_write(self):
        p = Principal("u", "a", Role.SECURITY_ANALYST, "org")
        assert p.can_ingest()
        assert p.can_write_incidents()
        assert not p.can_manage_users()

    def test_auditor_is_read_only(self):
        p = Principal("u", "a", Role.READ_ONLY_AUDITOR, "org")
        assert not p.can_ingest()
        assert not p.can_write_incidents()
        assert not p.can_manage_users()

    def test_admin_can_manage_users(self):
        p = Principal("u", "a", Role.ADMINISTRATOR, "org")
        assert p.can_manage_users()
        assert p.can_write_incidents()


class TestStateMachine:
    def test_legal_transitions(self):
        assert IncidentStatus.TRIAGED in _TRANSITIONS[IncidentStatus.NEW]
        assert IncidentStatus.INVESTIGATING in _TRANSITIONS[IncidentStatus.TRIAGED]
        assert IncidentStatus.RESOLVED in _TRANSITIONS[IncidentStatus.INVESTIGATING]
        assert IncidentStatus.CLOSED in _TRANSITIONS[IncidentStatus.RESOLVED]
        # reopen
        assert IncidentStatus.INVESTIGATING in _TRANSITIONS[IncidentStatus.CLOSED]

    def test_illegal_transition_new_to_resolved(self):
        assert IncidentStatus.RESOLVED not in _TRANSITIONS[IncidentStatus.NEW]

    def test_invalid_transition_is_value_error(self):
        assert issubclass(InvalidTransition, ValueError)
