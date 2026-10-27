"""Authorization / identity context for clinical-access detection.

The detector is only as good as the context it is given. ``ClinicalContext``
is the validated identity, role, assignment, scope and shift information a
detector needs to distinguish legitimate access from anomalous access. In a
real deployment this is populated from authoritative HR / IAM / scheduling
systems; in tests it is produced from the synthetic organization.

Keeping this as an explicit, typed input (rather than hard-coding assumptions
in the detector) is what lets the same ``PatientAccessDetector`` run against
synthetic data today and real hospital context later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Set, Tuple


@dataclass(frozen=True)
class ActorProfile:
    actor_id: str
    actor_type: str
    role: str
    department: str
    assigned_patients: Set[str] = field(default_factory=set)
    # Documented care relationships (e.g. the provider was recorded on the
    # patient's admission). This is EVIDENCE of a clinical relationship, NOT a
    # grant of access authorization. Kept separate from ``assigned_patients``.
    care_relationships: Set[str] = field(default_factory=set)
    # Resource-id prefixes this (service) account is authorized to touch.
    authorized_resource_prefixes: Set[str] = field(default_factory=set)
    # Shift window in UTC hours [start, end); crosses midnight if start > end.
    shift: Tuple[int, int] = (0, 24)

    def is_on_shift(self, ts: datetime) -> bool:
        hour = ts.astimezone(timezone.utc).hour
        start, end = self.shift
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end

    def is_assigned(self, patient_ref: str) -> bool:
        return patient_ref in self.assigned_patients

    def has_care_relationship(self, patient_ref: str) -> bool:
        """Whether a documented care relationship exists. Does NOT imply the
        actor is authorized to access the record — only that the source data
        records a clinical association (e.g. an admission)."""
        return patient_ref in self.care_relationships

    def is_resource_in_scope(self, resource_id: str) -> bool:
        if not self.authorized_resource_prefixes:
            return True  # no scope restriction configured
        return any(resource_id.startswith(p) for p in self.authorized_resource_prefixes)


@dataclass
class ClinicalContext:
    """All authorization context the detector consumes."""

    actors: Dict[str, ActorProfile] = field(default_factory=dict)

    def profile(self, actor_id: str) -> ActorProfile | None:
        return self.actors.get(actor_id)

    @classmethod
    def from_synthetic_org(cls, org) -> "ClinicalContext":
        """Build context from a ``SyntheticOrg`` (test/demo convenience)."""
        actors: Dict[str, ActorProfile] = {}
        for aid, a in org.actors.items():
            prefixes = org.service_account_scopes.get(aid, set())
            actors[aid] = ActorProfile(
                actor_id=aid,
                actor_type=a.actor_type.value,
                role=a.role,
                department=a.department,
                assigned_patients=set(a.assigned_patients),
                authorized_resource_prefixes=set(prefixes),
                shift=(a.shift_start_hour, a.shift_end_hour),
            )
        return cls(actors=actors)
