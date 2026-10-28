"""Versioned investigation data model.

All models are pydantic v2 and carry an explicit ``schema_version`` so the
persisted representation can evolve safely. References to identities, patients,
resources, hosts and sessions are opaque/pseudonymous strings. No clinical
record content is represented here.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


# --- enums ------------------------------------------------------------------

class DataOrigin(str, Enum):
    """Distinguishes the provenance of telemetry. Never overstated."""

    SYNTHETIC = "synthetic"
    DEMO_DERIVED = "demo_derived"
    REAL = "real"
    UNSPECIFIED = "unspecified"


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class InvestigationActionType(str, Enum):
    ACKNOWLEDGE = "acknowledge"
    ASSIGN = "assign"
    ADD_NOTE = "add_note"
    STATUS_CHANGE = "status_change"
    DISPOSITION = "disposition"
    CLOSE = "close"
    REOPEN = "reopen"


# --- SecurityEvent ----------------------------------------------------------

class SecurityEvent(BaseModel):
    """Normalized security event accepted by the ingestion service.

    Fields the source does not provide are left null/unknown rather than
    invented. ``event_id`` is a stable platform id; ``source_event_id`` is the
    upstream id used (with source_type + organization) for idempotent dedup.
    """

    model_config = {"extra": "forbid"}

    schema_version: str = SCHEMA_VERSION
    event_id: str = Field(default_factory=lambda: _new_id("evt"))
    source_event_id: Optional[str] = None
    source_type: str
    event_timestamp: datetime
    ingestion_timestamp: datetime = Field(default_factory=_utcnow)
    identity_id: Optional[str] = None
    session_id: Optional[str] = None
    host_id: Optional[str] = None
    resource_reference: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    organization_id: str = "default"
    data_origin: DataOrigin = DataOrigin.UNSPECIFIED
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    normalized_attributes: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_timestamp", "ingestion_timestamp")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _to_utc(v)

    def dedup_key(self) -> str:
        """Idempotency key: same source event from same source+org dedups.

        Falls back to a content hash when the source provides no id, so a
        byte-identical replay is still deduplicated but distinct events are not
        accidentally merged.
        """
        if self.source_event_id:
            basis = f"{self.organization_id}|{self.source_type}|{self.source_event_id}"
        else:
            basis = "|".join(
                str(x)
                for x in (
                    self.organization_id,
                    self.source_type,
                    self.identity_id,
                    self.resource_reference,
                    self.action,
                    self.outcome,
                    self.event_timestamp.isoformat(),
                )
            )
        return hashlib.sha256(basis.encode()).hexdigest()


# --- DetectionFinding record (compat adapter) -------------------------------

class DetectionFindingRecord(BaseModel):
    """Persisted, platform-level view of a detector finding.

    The engine's existing ``DetectionFinding`` is a dataclass (rule_id,
    rule_name, severity, confidence, source_type, raw_evidence, mappings,
    timestamp, host, description). This record is a documented, tested adapter
    over it that adds investigation-layer fields without modifying the engine.
    """

    model_config = {"extra": "forbid"}

    schema_version: str = SCHEMA_VERSION
    finding_id: str = Field(default_factory=lambda: _new_id("fnd"))
    rule_id: str
    rule_version: str = "unversioned"
    severity: IncidentSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str = ""
    evidence_references: Dict[str, Any] = Field(default_factory=dict)
    mapped_attack_techniques: List[str] = Field(default_factory=list)
    detection_timestamp: datetime = Field(default_factory=_utcnow)
    affected_identity: Optional[str] = None
    affected_resource: Optional[str] = None
    disposition: Optional[str] = None
    organization_id: str = "default"
    source_event_id: Optional[str] = None

    @field_validator("detection_timestamp")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _to_utc(v)

    @classmethod
    def from_engine_finding(
        cls,
        finding: Any,
        *,
        organization_id: str = "default",
        rule_version: str = "unversioned",
        source_event_id: Optional[str] = None,
    ) -> "DetectionFindingRecord":
        """Adapt an engine ``DetectionFinding`` dataclass into a record.

        Reads only documented attributes; evidence is passed through as-is
        (detectors are responsible for redaction, e.g. healthcare's
        ``redacted_evidence``). ATT&CK technique ids are extracted from mappings
        when present.
        """
        severity = str(getattr(finding, "severity", "INFO")).upper()
        if severity not in IncidentSeverity.__members__:
            severity = "INFO"
        techniques: List[str] = []
        for m in getattr(finding, "mappings", []) or []:
            tid = getattr(m, "technique_id", None)
            if tid:
                techniques.append(tid)
        evidence = dict(getattr(finding, "raw_evidence", {}) or {})
        return cls(
            rule_id=getattr(finding, "rule_id", "UNKNOWN"),
            rule_version=rule_version,
            severity=IncidentSeverity(severity),
            confidence=float(getattr(finding, "confidence", 0.0) or 0.0),
            description=getattr(finding, "description", "") or "",
            evidence_references=evidence,
            mapped_attack_techniques=techniques,
            affected_identity=evidence.get("actor_id") or evidence.get("identity_id"),
            affected_resource=evidence.get("resource_id")
            or evidence.get("patient_ref"),
            organization_id=organization_id,
            source_event_id=source_event_id,
        )


# --- SecurityIncident -------------------------------------------------------

class SecurityIncident(BaseModel):
    model_config = {"extra": "forbid"}

    schema_version: str = SCHEMA_VERSION
    incident_id: str = Field(default_factory=lambda: _new_id("inc"))
    title: str
    description: str = ""
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    assigned_analyst: Optional[str] = None
    related_findings: List[str] = Field(default_factory=list)
    related_events: List[str] = Field(default_factory=list)
    correlation_reason: str = ""
    affected_entities: Dict[str, Any] = Field(default_factory=dict)
    resolution_summary: Optional[str] = None
    close_reason: Optional[str] = None
    organization_id: str = "default"
    # Stable key used for idempotent incident creation by the correlator.
    correlation_key: Optional[str] = None

    @field_validator("created_at", "updated_at", "first_seen", "last_seen")
    @classmethod
    def _tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return _to_utc(v) if v is not None else None


# --- InvestigationAction ----------------------------------------------------

class InvestigationAction(BaseModel):
    """Durable audit record of an analyst action on an incident."""

    model_config = {"extra": "forbid"}

    schema_version: str = SCHEMA_VERSION
    action_id: str = Field(default_factory=lambda: _new_id("act"))
    incident_id: str
    analyst_id: str
    action_type: InvestigationActionType
    previous_value: Optional[str] = None
    updated_value: Optional[str] = None
    note: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utcnow)
    organization_id: str = "default"

    @field_validator("timestamp")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        return _to_utc(v)
