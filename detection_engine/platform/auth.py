"""Authentication and role-based authorization.

Uses passlib (bcrypt) for password hashing and python-jose for signed JWTs —
established libraries rather than custom cryptography. Authorization is enforced
server-side via FastAPI dependencies. Every protected operation resolves the
caller's organization and role; organization isolation is applied in the data
layer by always scoping queries to the caller's organization_id.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import bcrypt
from jose import JWTError, jwt

# bcrypt operates on bytes and rejects secrets longer than 72 bytes. We encode
# and bound the password explicitly rather than relying on a wrapper layer.
_BCRYPT_MAX_BYTES = 72

# The signing secret MUST be provided in any non-local deployment. A random
# per-process default is used only so local/dev startup does not crash; it
# invalidates tokens across restarts, which is safe-by-default.
JWT_SECRET = os.environ.get("AEGIS_JWT_SECRET", os.urandom(32).hex())
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_MINUTES = int(os.environ.get("AEGIS_TOKEN_TTL_MIN", "60"))


class Role(str, Enum):
    ADMINISTRATOR = "administrator"
    SECURITY_ANALYST = "security_analyst"
    READ_ONLY_AUDITOR = "read_only_auditor"


# Capability matrix: which roles may perform which action classes.
_CAN_WRITE_INCIDENTS = {Role.ADMINISTRATOR, Role.SECURITY_ANALYST}
_CAN_INGEST = {Role.ADMINISTRATOR, Role.SECURITY_ANALYST}
_CAN_MANAGE_USERS = {Role.ADMINISTRATOR}
# All three roles may read incidents/evidence within their org.


def _to_bytes(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_to_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_to_bytes(password), password_hash.encode("utf-8"))
    except Exception:
        return False


def create_access_token(*, user_id: str, username: str, role: str, organization_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "org": organization_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


class Principal:
    """The authenticated caller resolved from a token."""

    def __init__(self, user_id: str, username: str, role: Role, organization_id: str):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.organization_id = organization_id

    # --- capability checks ---
    def can_ingest(self) -> bool:
        return self.role in _CAN_INGEST

    def can_write_incidents(self) -> bool:
        return self.role in _CAN_WRITE_INCIDENTS

    def can_manage_users(self) -> bool:
        return self.role in _CAN_MANAGE_USERS


def decode_token(token: str) -> Optional[Principal]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None
    try:
        role = Role(payload["role"])
    except (KeyError, ValueError):
        return None
    return Principal(
        user_id=payload.get("sub", ""),
        username=payload.get("username", ""),
        role=role,
        organization_id=payload.get("org", ""),
    )
