"""Bootstrap helpers: build the app with real detectors and seed users.

Separated from ``api`` so tests and the deployment entrypoint share one way to
wire the ATT&CK pipeline and the clinical detector, and to create initial users.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from . import auth, db
from .api import create_app


@lru_cache(maxsize=1)
def _cached_attack_index():
    """Load the ATT&CK v19 index once per process (it is immutable and ~9s to
    parse). Reused across app builds/tests to avoid repeated bundle parsing."""
    from attack_v19_core import ATTACKIndex, ATTACKLoader

    return ATTACKIndex(ATTACKLoader())


def _default_pipeline_factory():
    from ..pipeline import DetectionPipeline

    return DetectionPipeline(_cached_attack_index())


def _default_clinical_detector_factory(clinical_context=None):
    from ..healthcare.detector import PatientAccessDetector

    return PatientAccessDetector(context=clinical_context, index=_cached_attack_index())


def build_app(clinical_context=None):
    return create_app(
        pipeline_factory=_default_pipeline_factory,
        clinical_detector_factory=lambda: _default_clinical_detector_factory(clinical_context),
    )


def seed_user(
    session,
    *,
    user_id: str,
    username: str,
    password: str,
    role: str,
    organization_id: str = "default",
) -> db.UserRow:
    """Create (or return existing) a user with a hashed password."""
    existing = session.query(db.UserRow).filter_by(username=username).one_or_none()
    if existing is not None:
        return existing
    row = db.UserRow(
        id=user_id,
        username=username,
        password_hash=auth.hash_password(password),
        role=role,
        organization_id=organization_id,
        is_active=True,
    )
    session.add(row)
    session.commit()
    return row


def ensure_schema(engine: Optional[object] = None) -> None:
    """Create all tables if absent (dev/test convenience; prod uses Alembic)."""
    eng = engine or db.make_engine()
    db.create_all(eng)
