"""Signed-token regression tests for strict identity and tenant boundaries."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest

from detection_engine.platform import auth


def claims():
    now = datetime.now(timezone.utc)
    return {
        "sub": "user-1",
        "username": "analyst",
        "org": "tenant-1",
        "role": "security_analyst",
        "tv": 0,
        "iss": auth.JWT_ISSUER,
        "aud": auth.JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }


def sign(payload):
    return jwt.encode(payload, auth.JWT_SECRET, algorithm=auth.JWT_ALGORITHM)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("tv", None),
        ("tv", True),
        ("tv", -1),
        ("tv", "0"),
        ("tv", 0.0),
        ("tv", []),
        ("org", []),
        ("org", " "),
        ("username", None),
        ("username", " "),
        ("sub", ""),
        ("role", []),
        ("iat", None),
        ("exp", []),
    ],
)
def test_invalid_signed_claim_rejected(name, value):
    assert auth.decode_token(sign({**claims(), name: value})) is None


@pytest.mark.parametrize("name", ["tv", "sub", "org", "username", "role"])
def test_missing_identity_claim_rejected(name):
    payload = claims()
    del payload[name]
    assert auth.decode_token(sign(payload)) is None


def test_valid_token_and_authoritative_role():
    token = sign(claims())
    row = SimpleNamespace(
        id="user-1", username="analyst", organization_id="tenant-1",
        role="read_only_auditor", is_active=True, token_version=0,
    )
    principal = auth.resolve_principal(token, row)
    assert principal is not None
    assert principal.role == auth.Role.READ_ONLY_AUDITOR
    assert not principal.can_write_incidents()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("organization_id", "tenant-2"),
        ("id", "user-2"),
        ("token_version", 1),
        ("is_active", False),
    ],
)
def test_stale_or_mismatched_principal_rejected(name, value):
    token = sign(claims())
    values = {
        "id": "user-1", "username": "analyst", "organization_id": "tenant-1",
        "role": "security_analyst", "is_active": True, "token_version": 0,
    }
    values[name] = value
    assert auth.resolve_principal(token, SimpleNamespace(**values)) is None
