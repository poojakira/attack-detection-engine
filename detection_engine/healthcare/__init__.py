"""Healthcare clinical-access security detection module.

This subpackage is intentionally decoupled from the automotive / CAN / firmware
detectors. It defines a normalized clinical-access security-event schema, a
labeled synthetic event generator, and deterministic detectors that operate on
that schema. It shares the engine's finding contract (``DetectionFinding``) and
plugs into ``DetectionPipeline`` as its own telemetry source.

Design constraints:
  * No patient PII by design. Patients and actors are referenced by opaque,
    caller-supplied pseudonymous identifiers only. The schema actively rejects
    common plaintext-PII field names.
  * Correlation-ready: every event exposes stable identity / resource /
    session / host / time keys.
  * FHIR-forward: field semantics align with FHIR R4 ``AuditEvent`` so a real
    hospital audit feed can be normalized into the same schema later.
"""

from .schema import (
    ClinicalAccessEvent,
    AccessAction,
    AccessOutcome,
    ActorType,
    PIIValidationError,
)

__all__ = [
    "ClinicalAccessEvent",
    "AccessAction",
    "AccessOutcome",
    "ActorType",
    "PIIValidationError",
]
