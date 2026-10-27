"""Authentication and role-based authorization (Milestone D hardened).

Design decisions:
  * Passwords are hashed with bcrypt, but pre-hashed with SHA-256+base64 first
    so the full password (any length, any Unicode) contributes entropy without
    hitting bcrypt's 72-byte input limit and WITHOUT silent truncation. New
    hashes carry a ``v2$`` prefix; legacy un-prefixed bcrypt hashes still verify
    (migration-safe), so existing accounts keep working.
  * JWTs use an explicit single-algorithm allowlist and carry iss/aud plus a
    ``tv`` (token_version) claim. ``decode_token`` validates signature, alg,
    exp, iat, iss, aud and required claims, failing closed otherwise.
  * ``resolve_principal`` re-reads the user from the database on every request:
    a disabled account or a bumped ``token_version`` (role/org change, forced
    logout) immediately stops authorizing, closing the stateless-token window.
  * A login throttle limits brute-force / credential-stuffing by (username, ip).

Secrets and tokens are never logged. Authentication errors are generic.
"""

from __future__ import annotations

import base64
import hashlib
import os
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import bcrypt
from jose import JWTError, jwt

JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.environ.get("AEGIS_JWT_ISSUER", "aegis-healthsec")
JWT_AUDIENCE = os.environ.get("AEGIS_JWT_AUDIENCE", "aegis-healthsec-api")
ACCESS_TOKEN_TTL_MINUTES = int(os.environ.get("AEGIS_TOKEN_TTL_MIN", "60"))

# Minimum acceptable signing-secret length (bytes) when a secret is provided.
_MIN_SECRET_LEN = 32


def _load_secret() -> str:
    secret = os.environ.get("AEGIS_JWT_SECRET")
    if secret:
        return secret
    # Dev-only fallback: a random per-process secret so local startup does not
    # crash. It invalidates tokens across restarts (safe by default). Deployment
    # entrypoints MUST set AEGIS_JWT_SECRET (enforced in require_secure_config).
    return os.urandom(32).hex()


JWT_SECRET = _load_secret()


def require_secure_config() -> None:
    """Fail closed on insecure configuration. Called by the deployment server
    entrypoint. Raises RuntimeError rather than silently using a weak default."""
    secret = os.environ.get("AEGIS_JWT_SECRET")
    if not secret:
        raise RuntimeError(
            "AEGIS_JWT_SECRET is required in a deployment; refusing to start with "
            "an ephemeral development secret."
        )
    if len(secret) < _MIN_SECRET_LEN:
        raise RuntimeError(
            f"AEGIS_JWT_SECRET must be at least {_MIN_SECRET_LEN} characters."
        )


class Role(str, Enum):
    ADMINISTRATOR = "administrator"
    SECURITY_ANALYST = "security_analyst"
    READ_ONLY_AUDITOR = "read_only_auditor"


_CAN_WRITE_INCIDENTS = {Role.ADMINISTRATOR, Role.SECURITY_ANALYST}
_CAN_INGEST = {Role.ADMINISTRATOR, Role.SECURITY_ANALYST}
_CAN_MANAGE_USERS = {Role.ADMINISTRATOR}


# --- password hashing -------------------------------------------------------

_V2_PREFIX = "v2$"


def _prehash(password: str) -> bytes:
    """SHA-256 of the UTF-8 password, base64-encoded (44 bytes, < 72).

    This removes bcrypt's 72-byte truncation ambiguity: the entire password
    contributes to the digest, so two long passwords that share a 72-byte prefix
    produce different hashes.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    bcrypt_hash = bcrypt.hashpw(_prehash(password), bcrypt.gensalt()).decode("utf-8")
    return _V2_PREFIX + bcrypt_hash


def verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith(_V2_PREFIX):
            bcrypt_hash = stored[len(_V2_PREFIX):].encode("utf-8")
            return bcrypt.checkpw(_prehash(password), bcrypt_hash)
        # Legacy (Milestone C) hash: raw bcrypt of the first 72 password bytes.
        # Still verifies so existing accounts work; re-hash on next password set.
        return bcrypt.checkpw(password.encode("utf-8")[:72], stored.encode("utf-8"))
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """True if a stored hash uses the legacy scheme and should be upgraded."""
    return not stored.startswith(_V2_PREFIX)


# --- tokens -----------------------------------------------------------------

def create_access_token(
    *, user_id: str, username: str, role: str, organization_id: str, token_version: int = 0
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "org": organization_id,
        "tv": token_version,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


class Principal:
    """The authenticated caller. ``token_version`` reflects the token's claim;
    ``resolve_principal`` validates it against the database."""

    def __init__(self, user_id: str, username: str, role: Role, organization_id: str, token_version: int = 0):
        self.user_id = user_id
        self.username = username
        self.role = role
        self.organization_id = organization_id
        self.token_version = token_version

    def can_ingest(self) -> bool:
        return self.role in _CAN_INGEST

    def can_write_incidents(self) -> bool:
        return self.role in _CAN_WRITE_INCIDENTS

    def can_manage_users(self) -> bool:
        return self.role in _CAN_MANAGE_USERS


def decode_token(token: str) -> Optional[Principal]:
    """Validate signature/alg/exp/iat/iss/aud and required claims. Returns a
    Principal built from CLAIMS ONLY. Callers that touch data MUST additionally
    call resolve_principal to re-validate against the database."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "sub", "role", "org"]},
        )
    except JWTError:
        return None
    try:
        role = Role(payload["role"])
    except (KeyError, ValueError):
        return None
    sub = payload.get("sub")
    org = payload.get("org")
    if not sub or not org:
        return None
    return Principal(
        user_id=sub,
        username=payload.get("username", ""),
        role=role,
        organization_id=org,
        token_version=int(payload.get("tv", 0)),
    )


def resolve_principal(token: str, user_row) -> Optional[Principal]:
    """Re-validate a decoded token against the authoritative user record.

    ``user_row`` is the DB row for the token's subject (or None if not found).
    Fails closed if the user is missing, disabled, the token_version is stale,
    or the role/org no longer match the database. This closes the window where a
    disabled account or changed role/org could still be used until expiry.
    """
    principal = decode_token(token)
    if principal is None or user_row is None:
        return None
    if not getattr(user_row, "is_active", False):
        return None
    if int(getattr(user_row, "token_version", 0)) != principal.token_version:
        return None
    # Authoritative role/org come from the database, not the token.
    try:
        db_role = Role(user_row.role)
    except ValueError:
        return None
    return Principal(
        user_id=user_row.id,
        username=user_row.username,
        role=db_role,
        organization_id=user_row.organization_id,
        token_version=int(getattr(user_row, "token_version", 0)),
    )


# --- login throttle ---------------------------------------------------------

class LoginThrottle:
    """In-memory sliding-window login limiter with temporary lockout.

    Keyed by (username, client_ip). Counts failures; after ``max_failures``
    within ``window`` seconds the key is locked for ``lockout`` seconds.
    Successful logins clear the counter. State is per-process and resets on
    restart — a documented limitation; a multi-process deployment should back
    this with a shared store (e.g. Redis).
    """

    def __init__(self, max_failures: int = 5, window: int = 300, lockout: int = 300):
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self._failures: dict[tuple, list[float]] = defaultdict(list)
        self._locked_until: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def is_locked(self, username: str, ip: str) -> bool:
        key = (username, ip)
        with self._lock:
            until = self._locked_until.get(key, 0)
            if until and time.time() < until:
                return True
            if until and time.time() >= until:
                self._locked_until.pop(key, None)
                self._failures.pop(key, None)
            return False

    def record_failure(self, username: str, ip: str) -> None:
        key = (username, ip)
        now = time.time()
        with self._lock:
            recent = [t for t in self._failures[key] if now - t < self.window]
            recent.append(now)
            self._failures[key] = recent
            if len(recent) >= self.max_failures:
                self._locked_until[key] = now + self.lockout

    def record_success(self, username: str, ip: str) -> None:
        key = (username, ip)
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)
