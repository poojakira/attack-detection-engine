"""HL7 FHIR R4 AuditEvent connector.

Reference: https://hl7.org/fhir/R4/auditevent.html

Accepts:
  * a single ``AuditEvent`` resource (JSON object),
  * a FHIR ``Bundle`` whose entries contain ``AuditEvent`` resources,
  * a JSON list of ``AuditEvent`` resources (e.g. parsed NDJSON lines).

Each AuditEvent is normalized into a ``SecurityEvent`` carrying only security
metadata — type/subtype, recorded time, agent (actor) reference, source,
action, outcome, and entity (resource) references — as pseudonymous tokens.
Clinical record *content* is never extracted. Malformed items are rejected
individually with a sanitized reason; they never abort the batch.

This connector does NOT assume an audit event proves malicious access, and does
NOT treat a care relationship as access authorization (that distinction lives in
the detector/context layer).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List

from ..models import DataOrigin, SecurityEvent
from .base import Connector, ConnectorError, ConnectorResult, ParsedItem

# FHIR AuditEvent.action single-character codes -> normalized action verbs.
_ACTION_MAP = {"C": "create", "R": "read", "U": "update", "D": "delete", "E": "execute"}
# FHIR AuditEvent.outcome codes (R4) -> normalized outcome.
_OUTCOME_MAP = {
    "0": "success",
    "4": "minor_failure",
    "8": "serious_failure",
    "12": "major_failure",
}


def _ref_token(ref_obj: Dict[str, Any]) -> str:
    """Extract an opaque reference token, never a human-readable display name."""
    if not isinstance(ref_obj, dict):
        return ""
    reference = str(ref_obj.get("reference", ""))
    if reference:
        return reference.split("/", 1)[-1]
    identifier = ref_obj.get("identifier", {})
    if isinstance(identifier, dict) and identifier.get("value"):
        return str(identifier["value"])
    return ""


def _ref_type(ref_obj: Dict[str, Any]) -> str:
    if not isinstance(ref_obj, dict):
        return ""
    return str(ref_obj.get("reference", "")).split("/", 1)[0]


class FhirAuditEventConnector(Connector):
    source_type = "fhir_audit_event"
    connector_version = "1.1"

    def parse(
        self, payload: Any, *, organization_id: str, max_items: int
    ) -> ConnectorResult:
        result = ConnectorResult(self.source_type, self.connector_version)
        resources = self._extract_resources(payload)
        if len(resources) > max_items:
            raise ConnectorError(f"payload exceeds max_items={max_items}")
        for idx, resource in enumerate(resources):
            try:
                event = self._normalize(resource, organization_id)
                from ...healthcare.schema import ClinicalAccessEvent

                ClinicalAccessEvent.model_validate(event.normalized_attributes)
                result.items.append(ParsedItem(index=idx, event=event))
            except Exception as exc:
                # Sanitized, bounded error message (no payload echo).
                result.items.append(ParsedItem(index=idx, error=self._reason(exc)))
        return result

    @staticmethod
    def _reason(exc: Exception) -> str:
        # Pydantic/type errors can contain source values. Never echo them.
        return (
            str(exc)[:200]
            if type(exc) is ValueError
            else "invalid or unsupported AuditEvent metadata"
        )

    def _extract_resources(self, payload: Any) -> List[Any]:
        """Return a flat list of AuditEvent resources from any supported shape."""
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            raise ConnectorError("payload must be a FHIR resource, Bundle, or list")
        rtype = payload.get("resourceType")
        if rtype == "AuditEvent":
            return [payload]
        if rtype == "Bundle":
            entries = payload.get("entry", [])
            if not isinstance(entries, list):
                raise ConnectorError("Bundle.entry must be an array")
            return [
                entry.get("resource") if isinstance(entry, dict) else None
                for entry in entries
            ]
        raise ConnectorError("unsupported resourceType; expected AuditEvent or Bundle")

    def _normalize(self, res: Dict[str, Any], organization_id: str) -> SecurityEvent:
        if not isinstance(res, dict) or res.get("resourceType") != "AuditEvent":
            raise ValueError("resource is not an AuditEvent")

        # Recorded timestamp is REQUIRED by FHIR R4; reject if absent/invalid
        # rather than inventing one.
        recorded = res.get("recorded")
        if not isinstance(recorded, str):
            raise ValueError("AuditEvent.recorded (timestamp) is required")
        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
            recorded,
        ):
            raise ValueError(
                "AuditEvent.recorded requires an instant with explicit timezone"
            )
        try:
            ts = datetime.fromisoformat(recorded.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("AuditEvent.recorded is not a valid ISO-8601 timestamp")

        agents = res.get("agent") or []
        if not isinstance(agents, list) or not agents:
            raise ValueError("AuditEvent.agent is required")
        if any(not isinstance(agent, dict) for agent in agents):
            raise ValueError("AuditEvent.agent entries must be objects")
        primary = agents[0]
        actor_id = _ref_token(primary.get("who", {})) or None
        network = (
            primary.get("network", {})
            if isinstance(primary.get("network"), dict)
            else {}
        )

        # type/subtype (Coding) -> compact subtype strings (metadata only).
        ev_type = res.get("type", {})
        type_code = ev_type.get("code") if isinstance(ev_type, dict) else None
        subtypes = res.get("subtype", []) or []
        if not isinstance(subtypes, list) or any(
            not isinstance(s, dict) for s in subtypes
        ):
            raise ValueError("AuditEvent.subtype must contain Coding objects")
        subtype_codes = [
            s.get("code") for s in subtypes if isinstance(s, dict) and s.get("code")
        ]

        # First Patient entity -> patient_ref; first non-patient -> resource.
        patient_ref = None
        resource_ref = None
        resource_type = ""
        entities = res.get("entity", [])
        if not isinstance(entities, list):
            raise ValueError("AuditEvent.entity must be an array")
        for ent in entities:
            what = ent.get("what", {}) if isinstance(ent, dict) else {}
            token = _ref_token(what)
            rtype = _ref_type(what)
            if rtype == "Patient" and patient_ref is None:
                patient_ref = token
            elif resource_ref is None and token:
                resource_ref = token
                resource_type = rtype
        resource_reference = resource_ref or patient_ref

        source = res.get("source", {})
        source_id = _ref_token(
            source.get("observer", {}) if isinstance(source, dict) else {}
        )

        for key, mapping in (("action", _ACTION_MAP), ("outcome", _OUTCOME_MAP)):
            if key in res and (
                not isinstance(res[key], str) or res[key] not in mapping
            ):
                raise ValueError(f"AuditEvent.{key} has an unsupported R4 code")
        action = _ACTION_MAP.get(res.get("action", ""), "unknown")
        outcome = _OUTCOME_MAP.get(res.get("outcome", ""), "unknown")

        return SecurityEvent(
            source_type=self.source_type,
            source_event_id=res.get("id"),
            event_timestamp=ts,
            identity_id=actor_id,
            session_id=source_id or None,
            host_id=None,
            resource_reference=resource_reference,
            action=action,
            outcome=outcome,
            organization_id=organization_id,  # from caller, never the payload
            data_origin=DataOrigin.UNSPECIFIED,
            source_metadata={
                "fhir_type_code": type_code,
                "fhir_subtype_codes": subtype_codes,
                "source_ip": str(network.get("address", "")) or None,
                "connector_version": self.connector_version,
            },
            normalized_attributes={
                # Clinical-access shape for the existing detector (pseudonymous).
                "actor_id": actor_id or "unknown",
                "patient_ref": patient_ref or resource_reference or "unknown",
                "resource_id": resource_reference or "unknown",
                "resource_type": resource_type,
                "action": action,
                "outcome": outcome,
                "timestamp": ts.isoformat(),
                "data_origin": "unspecified",
            },
        )
