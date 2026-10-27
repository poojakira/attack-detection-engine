"""ASGI entrypoint for the Aegis investigation API.

Run with:  uvicorn detection_engine.platform.server:app
Builds the app with the real detection pipeline + clinical detector. The ATT&CK
index is loaded once (cached). An optional admin user can be seeded from
environment variables on startup for first-run bootstrap.
"""

from __future__ import annotations

import os

from . import db
from .bootstrap import build_app, ensure_schema, seed_user


def _maybe_seed_admin() -> None:
    username = os.environ.get("AEGIS_ADMIN_USER")
    password = os.environ.get("AEGIS_ADMIN_PASSWORD")
    org = os.environ.get("AEGIS_ADMIN_ORG", "default")
    if not username or not password:
        return
    engine = db.make_engine()
    session = db.make_session_factory(engine)()
    try:
        seed_user(
            session,
            user_id="admin-bootstrap",
            username=username,
            password=password,
            role="administrator",
            organization_id=org,
        )
    finally:
        session.close()
        engine.dispose()


# Schema is normally applied via Alembic in the container entrypoint; ensure_schema
# is a safe fallback for environments where migrations were already run.
if os.environ.get("AEGIS_ENSURE_SCHEMA", "0") == "1":
    ensure_schema()

_maybe_seed_admin()

app = build_app()
