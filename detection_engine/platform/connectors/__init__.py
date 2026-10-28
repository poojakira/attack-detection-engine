"""Telemetry connector framework.

A connector turns a specific source format (e.g. FHIR R4 AuditEvent) into the
platform's normalized ``SecurityEvent`` list, with per-item error isolation.
Connectors do not persist, detect, or correlate — the ingestion service does
that. This keeps the lifecycle uniform across sources:

    Source → Validate → Parse → Normalize → (ingestion:) Dedup → Detect →
    Correlate → Persist → Investigate.

Design rules enforced here:
  * Preserve source provenance; never fabricate identities/timestamps.
  * Unknown ≠ negative observation (missing fields stay None).
  * Organization is supplied by the authenticated caller, never trusted from
    the payload.
  * Malformed items are rejected individually with a sanitized reason.
"""

from .base import (
    Connector,
    ConnectorError,
    ConnectorResult,
    ParsedItem,
)

__all__ = ["Connector", "ConnectorError", "ConnectorResult", "ParsedItem"]
