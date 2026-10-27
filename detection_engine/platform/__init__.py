"""Aegis HealthSec investigation platform.

This subpackage builds the end-to-end security investigation workflow on top of
the existing detection engine:

    ingest -> normalize -> detect -> correlate -> persist -> incident ->
    investigate -> resolve -> audit

It is domain-agnostic: it consumes the engine's ``DetectionFinding`` contract
and a normalized ``SecurityEvent`` so that healthcare, automotive, and other
detector domains share one investigation model. Patient/actor references are
pseudonymous; no clinical record content is stored in the investigation layer.
"""

from .models import (
    SCHEMA_VERSION,
    DetectionFindingRecord,
    IncidentSeverity,
    IncidentStatus,
    InvestigationAction,
    InvestigationActionType,
    SecurityEvent,
    SecurityIncident,
)

__all__ = [
    "SCHEMA_VERSION",
    "SecurityEvent",
    "DetectionFindingRecord",
    "SecurityIncident",
    "InvestigationAction",
    "InvestigationActionType",
    "IncidentSeverity",
    "IncidentStatus",
]
