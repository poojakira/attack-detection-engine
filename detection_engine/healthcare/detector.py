"""Deterministic patient-record access anomaly detector.

Operates on a batch of ``ClinicalAccessEvent`` records (supplied as dicts via
the pipeline, or as objects directly) using a ``ClinicalContext`` for
authorization ground truth. All rules are deterministic and explainable: each
finding records exactly which signal fired and the metadata that triggered it.

Design principles (per product requirements):
  * A clinician accessing several assigned patients is NOT malicious.
  * Documented break-glass / emergency access is surfaced as a REVIEW event,
    not automatically a high-severity malicious finding.
  * ATT&CK techniques are only attached where the signal genuinely supports the
    mapping (bulk export / exfiltration-shaped behavior). Access-pattern
    anomalies that do not map cleanly are emitted WITHOUT an ATT&CK mapping
    rather than inventing one.
  * No patient record content is placed in evidence — only pseudonymous
    identifiers and access metadata.

This detector does not subclass ``BaseDetector`` because its findings are
intentionally ATT&CK-optional; it builds mappings via the same
``ATTACKMappingBuilder`` only for the rules that justify one.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from ..base import DetectionFinding
from .context import ClinicalContext
from .schema import AccessAction, AccessOutcome, ClinicalAccessEvent


class PatientAccessDetector:
    """Deterministic clinical-access anomaly detector."""

    SOURCE_TYPE = "clinical_access"

    def __init__(
        self,
        context: Optional[ClinicalContext] = None,
        index: Any = None,
        *,
        bulk_access_threshold: int = 25,
        bulk_export_record_threshold: int = 1000,
        denial_streak_threshold: int = 3,
    ):
        self.context = context or ClinicalContext()
        self.bulk_access_threshold = bulk_access_threshold
        self.bulk_export_record_threshold = bulk_export_record_threshold
        self.denial_streak_threshold = denial_streak_threshold
        # Optional ATT&CK mapping builder; only used for exfil-shaped rules.
        self._mapping_builder = None
        if index is not None:
            from attack_v19_core.mapping import ATTACKMappingBuilder

            self._mapping_builder = ATTACKMappingBuilder(index)

    # --- Public API ---------------------------------------------------------

    def detect(self, data: List[Dict[str, Any]]) -> List[DetectionFinding]:
        events = self._coerce(data)
        findings: List[DetectionFinding] = []
        findings += self._rule_bulk_access(events)
        findings += self._rule_off_shift_unassigned(events)
        findings += self._rule_unassigned_access(events)
        findings += self._rule_break_glass_review(events)
        findings += self._rule_denied_then_success(events)
        findings += self._rule_service_account_scope(events)
        findings += self._rule_bulk_export(events)
        return findings

    # --- Coercion -----------------------------------------------------------

    def _coerce(self, data: List[Any]) -> List[ClinicalAccessEvent]:
        events: List[ClinicalAccessEvent] = []
        for rec in data:
            if isinstance(rec, ClinicalAccessEvent):
                events.append(rec)
            else:
                events.append(ClinicalAccessEvent.from_dict(rec))
        return events

    # --- Rules --------------------------------------------------------------

    def _rule_bulk_access(self, events: List[ClinicalAccessEvent]) -> List[DetectionFinding]:
        """High number of distinct patients read by one actor in the batch."""
        by_actor: Dict[str, set] = defaultdict(set)
        sample: Dict[str, ClinicalAccessEvent] = {}
        for e in events:
            if e.action == AccessAction.READ and e.outcome == AccessOutcome.SUCCESS:
                by_actor[e.actor_id].add(e.patient_ref)
                sample.setdefault(e.actor_id, e)
        findings = []
        for actor_id, patients in by_actor.items():
            if len(patients) >= self.bulk_access_threshold:
                ev = sample[actor_id]
                findings.append(
                    self._finding(
                        rule_id="HC-ACCESS-BULK",
                        rule_name="Unusually High Patient Record Access",
                        severity="HIGH",
                        confidence=0.8,
                        event=ev,
                        description=(
                            f"Actor {actor_id} read {len(patients)} distinct patient "
                            f"records in one window (threshold {self.bulk_access_threshold})."
                        ),
                        extra={"distinct_patients": len(patients)},
                    )
                )
        return findings

    def _rule_off_shift_unassigned(self, events: List[ClinicalAccessEvent]) -> List[DetectionFinding]:
        """Access outside the actor's shift AND outside their assigned panel,
        without break-glass."""
        findings = []
        for e in events:
            if e.break_glass:
                continue
            prof = self.context.profile(e.actor_id)
            if prof is None:
                continue
            if not prof.is_on_shift(e.timestamp) and not prof.is_assigned(e.patient_ref):
                findings.append(
                    self._finding(
                        rule_id="HC-ACCESS-OFFSHIFT",
                        rule_name="Off-Shift Access to Unassigned Patient",
                        severity="HIGH",
                        confidence=0.75,
                        event=e,
                        description=(
                            f"Actor {e.actor_id} accessed unassigned patient "
                            f"{e.patient_ref} outside their shift and without break-glass."
                        ),
                    )
                )
        return findings

    def _rule_unassigned_access(self, events: List[ClinicalAccessEvent]) -> List[DetectionFinding]:
        """Successful access to a patient outside the actor's panel, on-shift,
        without break-glass. Lower severity: could be legitimate cross-coverage,
        so this is a review signal, not a malicious verdict.

        A documented care relationship (e.g. a recorded admission link) is
        treated as a MITIGATING signal: it lowers severity/confidence and is
        recorded in the evidence. It is explicitly NOT treated as proof of
        access authorization — only ``assigned_patients`` grants clear it."""
        findings = []
        for e in events:
            if e.break_glass or e.outcome != AccessOutcome.SUCCESS:
                continue
            prof = self.context.profile(e.actor_id)
            if prof is None or prof.actor_type == "service_account":
                continue
            if prof.is_assigned(e.patient_ref):
                continue
            if prof.is_on_shift(e.timestamp):
                has_rel = prof.has_care_relationship(e.patient_ref)
                severity = "LOW" if has_rel else "MEDIUM"
                confidence = 0.35 if has_rel else 0.5
                rel_note = (
                    "a documented care relationship exists (admission link), which "
                    "lowers but does not clear this signal; the relationship is not "
                    "proof of access authorization"
                    if has_rel
                    else "no documented care relationship was found"
                )
                findings.append(
                    self._finding(
                        rule_id="HC-ACCESS-UNASSIGNED",
                        rule_name="Access to Unassigned Patient (Review)",
                        severity=severity,
                        confidence=confidence,
                        event=e,
                        description=(
                            f"Actor {e.actor_id} accessed patient {e.patient_ref} "
                            f"outside their authorized panel; {rel_note}. Flagged "
                            "for review."
                        ),
                        extra={"care_relationship": has_rel},
                    )
                )
        return findings

    def _rule_break_glass_review(self, events: List[ClinicalAccessEvent]) -> List[DetectionFinding]:
        """Break-glass usage is a documented emergency procedure. Surface it for
        review as INFO/LOW — explicitly NOT treated as malicious."""
        findings = []
        for e in events:
            if e.break_glass:
                findings.append(
                    self._finding(
                        rule_id="HC-ACCESS-BREAKGLASS",
                        rule_name="Break-Glass Emergency Access (Review)",
                        severity="LOW",
                        confidence=0.4,
                        event=e,
                        description=(
                            f"Actor {e.actor_id} used break-glass access for patient "
                            f"{e.patient_ref}. Expected to be reviewed, not auto-blocked."
                        ),
                    )
                )
        return findings

    def _rule_denied_then_success(self, events: List[ClinicalAccessEvent]) -> List[DetectionFinding]:
        """>= N consecutive denials for an (actor, resource) followed by a
        success — possible authorization probing."""
        seq: Dict[tuple, List[ClinicalAccessEvent]] = defaultdict(list)
        for e in sorted(events, key=lambda x: x.timestamp):
            seq[(e.actor_id, e.resource_id)].append(e)
        findings = []
        for (actor_id, resource_id), evs in seq.items():
            denials = 0
            for e in evs:
                if e.outcome == AccessOutcome.DENIED:
                    denials += 1
                elif e.outcome == AccessOutcome.SUCCESS:
                    if denials >= self.denial_streak_threshold:
                        findings.append(
                            self._finding(
                                rule_id="HC-ACCESS-DENYSUCCESS",
                                rule_name="Repeated Denials Then Success",
                                severity="HIGH",
                                confidence=0.8,
                                event=e,
                                description=(
                                    f"Actor {actor_id} was denied {denials} times on "
                                    f"resource {resource_id} then succeeded — possible "
                                    "authorization probing."
                                ),
                                extra={"denial_count": denials},
                            )
                        )
                    denials = 0
        return findings

    def _rule_service_account_scope(self, events: List[ClinicalAccessEvent]) -> List[DetectionFinding]:
        """Service account touching a resource outside its authorized prefix."""
        findings = []
        for e in events:
            prof = self.context.profile(e.actor_id)
            if prof is None or prof.actor_type != "service_account":
                continue
            if not prof.is_resource_in_scope(e.resource_id):
                findings.append(
                    self._finding(
                        rule_id="HC-IDENTITY-SVCSCOPE",
                        rule_name="Service Account Scope Violation",
                        severity="HIGH",
                        confidence=0.85,
                        event=e,
                        description=(
                            f"Service account {e.actor_id} accessed resource "
                            f"{e.resource_id} outside its authorized scope "
                            f"{sorted(prof.authorized_resource_prefixes)}."
                        ),
                    )
                )
        return findings

    def _rule_bulk_export(self, events: List[ClinicalAccessEvent]) -> List[DetectionFinding]:
        """High-volume export. This is exfiltration-shaped, so it is the one
        rule that attaches an ATT&CK technique (T1567 Exfiltration Over Web
        Service) when a mapping builder is available."""
        findings = []
        for e in events:
            if e.action == AccessAction.EXPORT and e.record_count >= self.bulk_export_record_threshold:
                findings.append(
                    self._finding(
                        rule_id="HC-EXFIL-BULKEXPORT",
                        rule_name="Suspicious Bulk Data Export",
                        severity="CRITICAL",
                        confidence=0.75,
                        event=e,
                        description=(
                            f"Actor {e.actor_id} exported {e.record_count} records in a "
                            f"single event (threshold {self.bulk_export_record_threshold}). "
                            "Requires investigation; a large export alone is not proof of "
                            "exfiltration."
                        ),
                        extra={"record_count": e.record_count},
                        attack_technique="T1567",
                    )
                )
        return findings

    # --- Finding construction ----------------------------------------------

    def _finding(
        self,
        *,
        rule_id: str,
        rule_name: str,
        severity: str,
        confidence: float,
        event: ClinicalAccessEvent,
        description: str,
        extra: Optional[Dict[str, Any]] = None,
        attack_technique: Optional[str] = None,
    ) -> DetectionFinding:
        evidence = event.redacted_evidence()
        evidence["contributing_signal"] = rule_id
        if extra:
            evidence.update(extra)
        mappings = []
        if attack_technique and self._mapping_builder is not None:
            m = self._mapping_builder.build(attack_technique, confidence)
            if m is not None:
                mappings = [m]
        return DetectionFinding(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity,
            confidence=confidence,
            source_type=self.SOURCE_TYPE,
            raw_evidence=evidence,
            mappings=mappings,
            timestamp=event.timestamp.isoformat(),
            host=event.source_host,
            description=description,
        )
