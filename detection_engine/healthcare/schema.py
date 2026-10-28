"""Normalized clinical-access security-event schema.

A ``ClinicalAccessEvent`` is the canonical, source-agnostic representation of a
single clinical-resource access as seen by a security monitor. It is NOT a
clinical record: it carries *who did what to which resource, when, from where,
and with what outcome* — the metadata a SOC needs — and deliberately excludes
patient-identifying content.

Pseudonymization contract
--------------------------
``actor_id``, ``patient_ref`` and ``resource_id`` MUST be opaque, stable tokens
(e.g. a hash or surrogate key) assigned upstream. This schema does not create
them and cannot verify they are truly de-identified, but it *does* reject
obvious plaintext PII (emails, SSNs, long digit runs that look like MRNs/phone
numbers) to catch accidental leakage at ingestion time.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class PIIValidationError(ValueError):
    """Raised when a field that must be pseudonymous appears to contain PII."""


class ActorType(str, Enum):
    """Kind of identity performing the access."""

    CLINICIAN = "clinician"
    NURSE = "nurse"
    ADMIN = "admin"
    SERVICE_ACCOUNT = "service_account"
    UNKNOWN = "unknown"


class AccessAction(str, Enum):
    """What the actor did. Aligned with FHIR AuditEvent.action (C/R/U/D/E)."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    EXPORT = "export"
    PRINT = "print"
    LOGIN = "login"


class AccessOutcome(str, Enum):
    """Result of the access. Aligned with FHIR AuditEvent.outcome semantics."""

    SUCCESS = "success"
    MINOR_FAILURE = "minor_failure"
    SERIOUS_FAILURE = "serious_failure"
    DENIED = "denied"


# Patterns used to reject accidental plaintext PII in pseudonymous fields.
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# A *bare* long digit run (the whole token is 9+ digits) resembles an unmasked
# MRN / phone / SSN-without-separators. A structured surrogate token that merely
# contains digits (e.g. "res-billing-0001", "sess-5a2b...") is allowed: good
# pseudonymization uses prefixed/alphanumeric surrogate keys, and callers that
# use purely numeric surrogate IDs are expected to prefix them.
_BARE_DIGIT_MRN_RE = re.compile(r"^\d{9,}$")
_PSEUDONYMOUS_FIELDS = ("actor_id", "patient_ref", "resource_id", "session_id")


def _looks_like_pii(value: str) -> Optional[str]:
    """Return a reason string if ``value`` looks like plaintext PII, else None."""
    if _EMAIL_RE.search(value):
        return "contains an email address"
    if _SSN_RE.search(value):
        return "contains an SSN-formatted value"
    if _BARE_DIGIT_MRN_RE.match(value):
        return "is a bare long digit run resembling an unmasked MRN/phone/SSN"
    return None


class ClinicalAccessEvent(BaseModel):
    """One normalized clinical-resource access event for security analysis."""

    model_config = {"extra": "forbid", "frozen": True}

    # --- Identity (correlation key: actor_id) ---
    actor_id: str = Field(..., min_length=1, description="Opaque actor token")
    actor_type: ActorType = ActorType.UNKNOWN
    actor_role: str = Field(
        default="", description="Functional role, e.g. 'cardiology_attending'"
    )
    actor_department: str = Field(default="", description="Org unit of the actor")

    # --- Resource (correlation keys: patient_ref, resource_id) ---
    patient_ref: str = Field(
        ..., min_length=1, description="Opaque patient surrogate token"
    )
    resource_id: str = Field(
        ..., min_length=1, description="Opaque resource token (record/report id)"
    )
    resource_type: str = Field(
        default="", description="e.g. 'Encounter', 'Observation', 'DocumentReference'"
    )

    # --- Action / outcome ---
    action: AccessAction
    outcome: AccessOutcome = AccessOutcome.SUCCESS
    record_count: int = Field(
        default=1, ge=0, description="Number of records touched by this event"
    )

    # --- Session / host / location (correlation keys: session_id, source_host) ---
    session_id: str = Field(default="", description="Opaque session token")
    source_host: str = Field(default="", description="Host/workstation identifier")
    source_ip: str = Field(default="", description="Source IP, if known")
    source_location: str = Field(
        default="", description="Logical location, e.g. 'ward_3' or 'remote_vpn'"
    )

    # --- Authorization context ---
    break_glass: bool = Field(
        default=False, description="Emergency/break-glass access was invoked"
    )
    authorized: Optional[bool] = Field(
        default=None,
        description="Whether the actor was authorized for this resource, if known",
    )

    # --- Time (correlation key: timestamp, always UTC) ---
    timestamp: datetime = Field(..., description="Event time, normalized to UTC")

    # --- Provenance (keeps synthetic vs real strictly distinguishable) ---
    data_origin: str = Field(
        default="unspecified",
        description="e.g. 'synthetic', 'fhir_audit_event', 'syslog' — never claims "
        "an origin it does not have",
    )

    @field_validator("actor_id", "patient_ref", "resource_id", "session_id")
    @classmethod
    def _reject_pii(cls, value: str, info) -> str:
        if value:
            reason = _looks_like_pii(value)
            if reason is not None:
                raise PIIValidationError(
                    f"field {info.field_name!r} must be pseudonymous but {reason}"
                )
        return value

    @field_validator("timestamp")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        # Normalize naive datetimes to UTC; convert aware datetimes to UTC.
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _consistency(self) -> "ClinicalAccessEvent":
        if self.action == AccessAction.EXPORT and self.record_count < 1:
            raise ValueError("export events must touch at least one record")
        return self

    # --- Correlation helpers -------------------------------------------------

    def correlation_keys(self) -> Dict[str, str]:
        """Stable keys a correlation layer can group on."""
        return {
            "identity": self.actor_id,
            "patient": self.patient_ref,
            "resource": self.resource_id,
            "session": self.session_id,
            "host": self.source_host,
        }

    def redacted_evidence(self) -> Dict[str, Any]:
        """Evidence dict safe to attach to a finding: metadata only, no record
        content, with pseudonymous identifiers preserved for investigation."""
        return {
            "actor_id": self.actor_id,
            "actor_type": self.actor_type.value,
            "actor_role": self.actor_role,
            "actor_department": self.actor_department,
            "patient_ref": self.patient_ref,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "action": self.action.value,
            "outcome": self.outcome.value,
            "record_count": self.record_count,
            "session_id": self.session_id,
            "source_host": self.source_host,
            "source_location": self.source_location,
            "break_glass": self.break_glass,
            "authorized": self.authorized,
            "timestamp": self.timestamp.isoformat(),
            "data_origin": self.data_origin,
        }

    # --- Ingestion adapters --------------------------------------------------

    @classmethod
    def from_dict(cls, record: Dict[str, Any]) -> "ClinicalAccessEvent":
        """Build from a plain dict (e.g. a pipeline telemetry record)."""
        return cls.model_validate(record)

    @classmethod
    def from_fhir_audit_event(
        cls, audit_event: Dict[str, Any], *, data_origin: str = "fhir_audit_event"
    ) -> "ClinicalAccessEvent":
        """Normalize a (subset of) FHIR R4 ``AuditEvent`` into this schema.

        This maps the fields a SOC needs. It intentionally does not import any
        patient-identifying ``.who.display`` names — only reference tokens. The
        caller remains responsible for ensuring references are pseudonymous.
        """
        action_map = {
            "C": AccessAction.CREATE,
            "R": AccessAction.READ,
            "U": AccessAction.UPDATE,
            "D": AccessAction.DELETE,
            "E": AccessAction.EXECUTE,
        }
        outcome_map = {
            "0": AccessOutcome.SUCCESS,
            "4": AccessOutcome.MINOR_FAILURE,
            "8": AccessOutcome.SERIOUS_FAILURE,
            "12": AccessOutcome.SERIOUS_FAILURE,
        }

        agents = audit_event.get("agent", []) or [{}]
        primary_agent = agents[0]
        entities = audit_event.get("entity", []) or []

        actor_id = _ref_token(primary_agent.get("who", {}))
        patient_ref = ""
        resource_id = ""
        resource_type = ""
        for ent in entities:
            ref = ent.get("what", {})
            token = _ref_token(ref)
            rtype = str(ref.get("reference", "")).split("/", 1)[0]
            if rtype == "Patient" and not patient_ref:
                patient_ref = token
            elif not resource_id:
                resource_id = token
                resource_type = rtype
        if not patient_ref:
            patient_ref = resource_id or "unknown"
        if not resource_id:
            resource_id = patient_ref

        source = audit_event.get("source", {})
        network = primary_agent.get("network", {})

        recorded = audit_event.get("recorded")
        timestamp = (
            datetime.fromisoformat(recorded.replace("Z", "+00:00"))
            if isinstance(recorded, str)
            else datetime.now(timezone.utc)
        )

        return cls(
            actor_id=actor_id or "unknown",
            actor_type=ActorType.UNKNOWN,
            patient_ref=patient_ref,
            resource_id=resource_id,
            resource_type=resource_type,
            action=action_map.get(str(audit_event.get("action", "R")), AccessAction.READ),
            outcome=outcome_map.get(
                str(audit_event.get("outcome", "0")), AccessOutcome.SUCCESS
            ),
            session_id=_ref_token(source) if source else "",
            source_ip=str(network.get("address", "")),
            timestamp=timestamp,
            data_origin=data_origin,
        )


def _ref_token(ref_obj: Dict[str, Any]) -> str:
    """Extract an opaque reference token from a FHIR Reference-like object,
    preferring the reference id over any human-readable display name."""
    reference = str(ref_obj.get("reference", ""))
    if reference:
        return reference.split("/", 1)[-1]
    identifier = ref_obj.get("identifier", {})
    if isinstance(identifier, dict) and identifier.get("value"):
        return str(identifier["value"])
    return ""
