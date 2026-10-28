"""Labeled synthetic clinical-access security-event generator.

Everything this module produces is FICTIONAL and SYNTHETIC. The actors, roles,
assignments, permissions, patients, and "attack" events are invented for
testing and demonstration. They are **not** real hospital security incidents,
**not** derived from any patient dataset, and **not** supplied by PhysioNet or
any data provider. The MIMIC-IV Demo dataset (see the ingestion adapter) is
de-identified *clinical* data and contains no security audit telemetry; it is
never used to fabricate the attack events below.

The generator emits:
  * a ``SyntheticOrg`` describing a fictional care organization and its
    legitimate actor -> patient-panel assignments (the authorization ground
    truth a detector needs), and
  * labeled streams of ``ClinicalAccessEvent`` for benign and attack scenarios.

Determinism: construct with a fixed ``seed`` for reproducible output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from random import Random
from typing import Dict, List, Set

from .schema import (
    AccessAction,
    AccessOutcome,
    ActorType,
    ClinicalAccessEvent,
)

SYNTHETIC_ORIGIN = "synthetic"


def _session_token(actor_id: str, ts: datetime) -> str:
    """Compact, pseudonymous session token.

    Uses a short hash of (actor, time-bucket) so repeated accesses by the same
    actor within an hour share a session, without embedding a raw epoch value
    that would trip the schema's long-digit-run PII guard.
    """
    import hashlib

    bucket = ts.astimezone(timezone.utc).strftime("%Y%m%d%H")
    digest = hashlib.sha256(f"{actor_id}:{bucket}".encode()).hexdigest()[:10]
    return f"sess-{digest}"


@dataclass
class SyntheticActor:
    actor_id: str
    actor_type: ActorType
    role: str
    department: str
    # Patients this actor is legitimately assigned to (authorization ground truth)
    assigned_patients: Set[str] = field(default_factory=set)
    # Shift window in UTC hours [start, end); crosses midnight if start > end
    shift_start_hour: int = 7
    shift_end_hour: int = 19


@dataclass
class SyntheticOrg:
    actors: Dict[str, SyntheticActor]
    patients: List[str]
    # Service accounts and the resource prefixes they are authorized to touch
    service_account_scopes: Dict[str, Set[str]]

    def is_on_shift(self, actor_id: str, ts: datetime) -> bool:
        actor = self.actors[actor_id]
        hour = ts.astimezone(timezone.utc).hour
        start, end = actor.shift_start_hour, actor.shift_end_hour
        if start <= end:
            return start <= hour < end
        return hour >= start or hour < end


class SyntheticAccessGenerator:
    """Generate a fictional org and labeled benign/attack access-event streams."""

    def __init__(self, seed: int = 1337):
        self._rng = Random(seed)
        self._seed = seed

    # --- Organization -------------------------------------------------------

    def build_org(
        self,
        n_clinicians: int = 6,
        n_nurses: int = 8,
        n_admins: int = 2,
        n_patients: int = 40,
        panel_size: int = 6,
    ) -> SyntheticOrg:
        departments = ["cardiology", "oncology", "emergency", "general_medicine"]
        patients = [f"pt-{i:04d}" for i in range(n_patients)]
        actors: Dict[str, SyntheticActor] = {}

        def assign_panel() -> Set[str]:
            return set(self._rng.sample(patients, k=min(panel_size, len(patients))))

        for i in range(n_clinicians):
            dept = self._rng.choice(departments)
            aid = f"clin-{i:03d}"
            actors[aid] = SyntheticActor(
                aid, ActorType.CLINICIAN, f"{dept}_attending", dept, assign_panel(),
                shift_start_hour=7, shift_end_hour=19,
            )
        for i in range(n_nurses):
            dept = self._rng.choice(departments)
            aid = f"nurse-{i:03d}"
            # mix of day and night shifts
            day = self._rng.random() < 0.6
            actors[aid] = SyntheticActor(
                aid, ActorType.NURSE, f"{dept}_rn", dept, assign_panel(),
                shift_start_hour=7 if day else 19,
                shift_end_hour=19 if day else 7,
            )
        for i in range(n_admins):
            aid = f"admin-{i:03d}"
            actors[aid] = SyntheticActor(
                aid, ActorType.ADMIN, "it_admin", "it", set(),
                shift_start_hour=8, shift_end_hour=18,
            )

        service_account_scopes = {
            "svc-billing": {"res-billing-"},
            "svc-lab-interface": {"res-lab-"},
        }
        for sid in service_account_scopes:
            actors[sid] = SyntheticActor(
                sid, ActorType.SERVICE_ACCOUNT, "integration", "platform", set(),
                shift_start_hour=0, shift_end_hour=24,
            )

        return SyntheticOrg(actors, patients, service_account_scopes)

    # --- Event helpers ------------------------------------------------------

    def _event(
        self,
        org: SyntheticOrg,
        actor_id: str,
        patient_ref: str,
        action: AccessAction,
        ts: datetime,
        *,
        resource_id: str | None = None,
        resource_type: str = "Encounter",
        outcome: AccessOutcome = AccessOutcome.SUCCESS,
        record_count: int = 1,
        break_glass: bool = False,
        session_id: str = "",
        source_host: str = "",
        source_location: str = "",
    ) -> ClinicalAccessEvent:
        actor = org.actors[actor_id]
        authorized = patient_ref in actor.assigned_patients or break_glass
        return ClinicalAccessEvent(
            actor_id=actor_id,
            actor_type=actor.actor_type,
            actor_role=actor.role,
            actor_department=actor.department,
            patient_ref=patient_ref,
            resource_id=resource_id or f"res-{patient_ref}-{action.value}",
            resource_type=resource_type,
            action=action,
            outcome=outcome,
            record_count=record_count,
            session_id=session_id or _session_token(actor_id, ts),
            source_host=source_host or f"ws-{actor.department}-1",
            source_location=source_location or actor.department,
            break_glass=break_glass,
            authorized=authorized,
            timestamp=ts,
            data_origin=SYNTHETIC_ORIGIN,
        )

    # --- Benign scenarios ---------------------------------------------------

    def benign_rounds(self, org: SyntheticOrg, day: datetime | None = None) -> List[ClinicalAccessEvent]:
        """Legitimate clinicians/nurses accessing their assigned patients
        during their shift. Expected: no malicious finding."""
        base = (day or datetime(2026, 10, 27, tzinfo=timezone.utc)).replace(
            hour=9, minute=0, second=0, microsecond=0
        )
        events: List[ClinicalAccessEvent] = []
        for actor_id, actor in org.actors.items():
            if actor.actor_type not in (ActorType.CLINICIAN, ActorType.NURSE):
                continue
            # access a handful of assigned patients during shift
            on_shift_hour = actor.shift_start_hour + 2
            ts = base.replace(hour=on_shift_hour % 24)
            for j, pt in enumerate(sorted(actor.assigned_patients)[:4]):
                events.append(
                    self._event(org, actor_id, pt, AccessAction.READ,
                                ts + timedelta(minutes=5 * j))
                )
        return events

    def benign_emergency_access(self, org: SyntheticOrg) -> List[ClinicalAccessEvent]:
        """A clinician uses a documented break-glass procedure for a patient
        outside their panel. Expected: classified as a review event, NOT
        automatically malicious."""
        clinician = next(
            a for a in org.actors.values() if a.actor_type == ActorType.CLINICIAN
        )
        unassigned = next(p for p in org.patients if p not in clinician.assigned_patients)
        ts = datetime(2026, 10, 27, 11, 0, tzinfo=timezone.utc)
        return [
            self._event(org, clinician.actor_id, unassigned, AccessAction.READ, ts,
                        break_glass=True, resource_type="Encounter")
        ]

    def benign_service_account(self, org: SyntheticOrg) -> List[ClinicalAccessEvent]:
        """A service account touching only resources within its scope."""
        ts = datetime(2026, 10, 27, 2, 0, tzinfo=timezone.utc)
        events = []
        for i in range(5):
            events.append(
                self._event(org, "svc-lab-interface", org.patients[i],
                            AccessAction.READ, ts + timedelta(minutes=i),
                            resource_id=f"res-lab-{i:04d}", resource_type="Observation")
            )
        return events

    # --- Attack scenarios (clearly labeled synthetic) -----------------------

    def attack_bulk_access(self, org: SyntheticOrg, count: int = 60) -> List[ClinicalAccessEvent]:
        """One identity reads an unusually large number of unrelated patients
        in a short window. Expected: reviewable anomaly."""
        clinician = next(
            a for a in org.actors.values() if a.actor_type == ActorType.CLINICIAN
        )
        ts = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
        events = []
        for i in range(count):
            pt = org.patients[i % len(org.patients)]
            events.append(
                self._event(org, clinician.actor_id, pt, AccessAction.READ,
                            ts + timedelta(seconds=10 * i))
            )
        return events

    def attack_off_shift_unassigned(self, org: SyntheticOrg) -> List[ClinicalAccessEvent]:
        """A day-shift actor accesses an unassigned patient in the middle of the
        night, no break-glass. Expected: off-hours + off-assignment anomaly."""
        day_actor = next(
            a for a in org.actors.values()
            if a.actor_type == ActorType.NURSE and a.shift_start_hour == 7
        )
        unassigned = next(p for p in org.patients if p not in day_actor.assigned_patients)
        ts = datetime(2026, 10, 27, 3, 0, tzinfo=timezone.utc)  # 03:00 UTC, off shift
        return [self._event(org, day_actor.actor_id, unassigned, AccessAction.READ, ts)]

    def attack_denied_then_success(self, org: SyntheticOrg) -> List[ClinicalAccessEvent]:
        """Repeated access denials for a resource followed by a success — a
        possible authorization-probing pattern. Expected: anomaly."""
        actor = next(a for a in org.actors.values() if a.actor_type == ActorType.NURSE)
        target = next(p for p in org.patients if p not in actor.assigned_patients)
        ts = datetime(2026, 10, 27, 13, 0, tzinfo=timezone.utc)
        events = []
        for i in range(4):
            events.append(
                self._event(org, actor.actor_id, target, AccessAction.READ,
                            ts + timedelta(seconds=30 * i),
                            outcome=AccessOutcome.DENIED,
                            resource_id=f"res-{target}-enc")
            )
        events.append(
            self._event(org, actor.actor_id, target, AccessAction.READ,
                        ts + timedelta(seconds=150),
                        outcome=AccessOutcome.SUCCESS,
                        resource_id=f"res-{target}-enc")
        )
        return events

    def attack_service_account_scope_violation(self, org: SyntheticOrg) -> List[ClinicalAccessEvent]:
        """A service account touches resources outside its authorized prefix.
        Expected: scope-violation anomaly."""
        ts = datetime(2026, 10, 27, 4, 0, tzinfo=timezone.utc)
        return [
            self._event(org, "svc-billing", org.patients[0], AccessAction.READ, ts,
                        resource_id="res-clinical-note-0001",
                        resource_type="DocumentReference")
        ]

    def attack_bulk_export(self, org: SyntheticOrg, records: int = 5000) -> List[ClinicalAccessEvent]:
        """A single high-volume export event outside established policy.
        Expected: investigable data-access alert."""
        actor = next(a for a in org.actors.values() if a.actor_type == ActorType.SERVICE_ACCOUNT)
        ts = datetime(2026, 10, 27, 5, 0, tzinfo=timezone.utc)
        return [
            self._event(org, actor.actor_id, org.patients[0], AccessAction.EXPORT, ts,
                        resource_id="res-bulk-export-0001",
                        resource_type="Bundle",
                        record_count=records)
        ]
