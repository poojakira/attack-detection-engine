"""SQLAlchemy 2.x persistence layer for the investigation platform.

Target operational database is PostgreSQL. The ORM models map the investigation
data model to durable tables with primary/foreign keys, indexes, and
idempotency constraints. The schema is created/evolved via Alembic
(``platform/migrations``); ``Base.metadata.create_all`` is used only for fast
test setup against an ephemeral database.

Connection is configured by the ``AEGIS_DATABASE_URL`` environment variable,
e.g. ``postgresql+psycopg://user:pass@host:5432/dbname``.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)
from sqlalchemy.types import JSON

DEFAULT_DATABASE_URL = "postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"


def get_database_url() -> str:
    return os.environ.get("AEGIS_DATABASE_URL", DEFAULT_DATABASE_URL)


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --- Identity / RBAC --------------------------------------------------------

class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), index=True)  # see platform.auth roles
    organization_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


# --- Events -----------------------------------------------------------------

class SecurityEventRow(Base):
    __tablename__ = "security_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    source_event_id: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingestion_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    identity_id: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    host_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    resource_reference: Mapped[Optional[str]] = mapped_column(String(256), index=True, nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    outcome: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    data_origin: Mapped[str] = mapped_column(String(32), default="unspecified")
    source_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized_attributes: Mapped[dict] = mapped_column(JSON, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(64), index=True)

    __table_args__ = (
        # Idempotent ingestion: one event per (org, dedup_key).
        UniqueConstraint("organization_id", "dedup_key", name="uq_event_org_dedup"),
    )


# --- Findings ---------------------------------------------------------------

class DetectionFindingRow(Base):
    __tablename__ = "detection_findings"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_version: Mapped[str] = mapped_column(String(32), default="unversioned")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_references: Mapped[dict] = mapped_column(JSON, default=dict)
    mapped_attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    detection_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    affected_identity: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    affected_resource: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    disposition: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    source_event_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


# --- Incidents --------------------------------------------------------------

class IncidentRow(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True, default="NEW")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_analyst: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    correlation_reason: Mapped[str] = mapped_column(Text, default="")
    affected_entities: Mapped[dict] = mapped_column(JSON, default=dict)
    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    close_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    correlation_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    # Optimistic-concurrency version to prevent lost updates.
    row_version: Mapped[int] = mapped_column(Integer, default=1)

    links: Mapped[list["IncidentFindingRow"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    actions: Mapped[list["InvestigationActionRow"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Idempotent incident creation per (org, correlation_key).
        UniqueConstraint("organization_id", "correlation_key", name="uq_incident_org_corr"),
        Index("ix_incident_org_status", "organization_id", "status"),
    )


class IncidentFindingRow(Base):
    __tablename__ = "incident_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("detection_findings.finding_id", ondelete="CASCADE"), index=True
    )
    incident: Mapped[IncidentRow] = relationship(back_populates="links")

    __table_args__ = (
        UniqueConstraint("incident_id", "finding_id", name="uq_incident_finding"),
    )


class IncidentEventRow(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[str] = mapped_column(
        ForeignKey("security_events.event_id", ondelete="CASCADE"), index=True
    )

    __table_args__ = (
        UniqueConstraint("incident_id", "event_id", name="uq_incident_event"),
    )


# --- Investigation audit ----------------------------------------------------

class InvestigationActionRow(Base):
    __tablename__ = "investigation_actions"

    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents.incident_id", ondelete="CASCADE"), index=True
    )
    analyst_id: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(32))
    previous_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    organization_id: Mapped[str] = mapped_column(String(64), index=True, default="default")

    incident: Mapped[IncidentRow] = relationship(back_populates="actions")


# --- Rule versions ----------------------------------------------------------

class RuleVersionRow(Base):
    __tablename__ = "rule_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    version: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (UniqueConstraint("rule_id", "version", name="uq_rule_version"),)


# --- Engine / session -------------------------------------------------------

def make_engine(url: Optional[str] = None, *, echo: bool = False):
    return create_engine(url or get_database_url(), echo=echo, future=True, pool_pre_ping=True)


def make_session_factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def create_all(engine) -> None:
    """Create all tables (test convenience; production uses Alembic)."""
    Base.metadata.create_all(engine)
