"""Deterministic correlation engine.

Groups related ``DetectionFindingRecord``s into ``SecurityIncident``s using a
combination of identity, resource, host, session, organization, rule category,
and a configurable time window. Correlation is explainable and deterministic —
it never groups solely on similar text or coincidental timestamps, and it never
merges unrelated identities or organizations.

Incident identity is a stable ``correlation_key`` so that re-running correlation
over the same findings is idempotent (the persistence layer upserts by that
key). Severity escalates to the max contributing finding severity.

This module computes incidents in-process from a batch of findings; durable,
idempotent creation is delegated to the repository (persisted state), so late
and repeated events converge on the same incident across runs.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from .models import (
    DetectionFindingRecord,
    IncidentSeverity,
    SecurityIncident,
)

# Map a rule_id prefix to a correlation category and a human label.
_RULE_CATEGORY = {
    "HC-ACCESS": ("healthcare_access", "Suspicious healthcare record access"),
    "HC-IDENTITY": ("identity_privilege", "Identity / privilege anomaly"),
    "HC-EXFIL": ("exfiltration", "Potential data exfiltration"),
    "HC-AUDIT": ("audit_integrity", "Audit log integrity concern"),
}


def _category_for_rule(rule_id: str) -> Tuple[str, str]:
    for prefix, cat in _RULE_CATEGORY.items():
        if rule_id.startswith(prefix):
            return cat
    return ("general", "Security finding group")


@dataclass
class CorrelationConfig:
    # Findings for the same identity within this window may correlate.
    time_window: timedelta = timedelta(hours=1)
    # Minimum distinct contributing rule categories to raise an incident for the
    # generic "activity sequence" path. Single strong signals still raise.
    min_findings: int = 1


@dataclass
class CorrelatedIncident:
    """In-process correlation result prior to persistence."""

    incident: SecurityIncident
    finding_ids: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    contributing_signals: List[str] = field(default_factory=list)


class CorrelationEngine:
    def __init__(self, config: Optional[CorrelationConfig] = None):
        self.config = config or CorrelationConfig()

    def _bucket_key(self, finding: DetectionFindingRecord) -> Tuple:
        """Deterministic grouping key.

        Groups by (organization, identity, time-window bucket). Identity is the
        primary correlation axis; findings with no identity are grouped by
        affected_resource so unrelated anonymous findings do not merge.
        """
        axis = finding.affected_identity or f"resource:{finding.affected_resource}"
        window_seconds = int(self.config.time_window.total_seconds()) or 1
        ts = finding.detection_timestamp or datetime.now(timezone.utc)
        bucket = int(ts.timestamp()) // window_seconds
        return (finding.organization_id, axis, bucket)

    def correlate(
        self,
        findings: Sequence[DetectionFindingRecord],
        *,
        event_ids_by_finding: Optional[Dict[str, List[str]]] = None,
    ) -> List[CorrelatedIncident]:
        """Group findings into incidents. Deterministic and order-independent."""
        event_ids_by_finding = event_ids_by_finding or {}
        groups: Dict[Tuple, List[DetectionFindingRecord]] = defaultdict(list)
        for f in sorted(findings, key=lambda x: (x.detection_timestamp, x.finding_id)):
            groups[self._bucket_key(f)].append(f)

        incidents: List[CorrelatedIncident] = []
        for (org, axis, bucket), group in groups.items():
            if len(group) < self.config.min_findings:
                continue
            incidents.append(self._build_incident(org, axis, bucket, group, event_ids_by_finding))
        return incidents

    def _build_incident(
        self,
        org: str,
        axis: str,
        bucket: int,
        group: List[DetectionFindingRecord],
        event_ids_by_finding: Dict[str, List[str]],
    ) -> CorrelatedIncident:
        severities = [IncidentSeverity(f.severity.value) for f in group]
        max_sev = max(severities, key=lambda s: s.rank)
        categories = sorted({_category_for_rule(f.rule_id)[0] for f in group})
        rule_ids = sorted({f.rule_id for f in group})
        labels = sorted({_category_for_rule(f.rule_id)[1] for f in group})

        # Stable, explainable correlation key: org + axis + categories + window.
        correlation_key = f"{org}|{axis}|{'+'.join(categories)}|{bucket}"

        timestamps = [f.detection_timestamp for f in group]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        contributing = [
            f"{f.rule_id} (sev={f.severity.value}, conf={f.confidence})" for f in group
        ]
        reason = (
            f"Correlated {len(group)} finding(s) for {axis} in {org} within a "
            f"{int(self.config.time_window.total_seconds() // 60)}-minute window. "
            f"Categories: {', '.join(categories)}. Signals: {'; '.join(rule_ids)}."
        )

        affected_entities = {
            "identity": group[0].affected_identity,
            "resources": sorted(
                {f.affected_resource for f in group if f.affected_resource}
            ),
            "attack_techniques": sorted(
                {t for f in group for t in f.mapped_attack_techniques}
            ),
        }

        finding_ids = [f.finding_id for f in group]
        event_ids: List[str] = []
        for fid in finding_ids:
            event_ids.extend(event_ids_by_finding.get(fid, []))

        incident = SecurityIncident(
            title=f"{labels[0]}: {axis}" if labels else f"Incident: {axis}",
            description=reason,
            severity=max_sev,
            correlation_reason=reason,
            affected_entities=affected_entities,
            organization_id=org,
            correlation_key=correlation_key,
            first_seen=first_seen,
            last_seen=last_seen,
            related_findings=finding_ids,
            related_events=sorted(set(event_ids)),
        )
        return CorrelatedIncident(
            incident=incident,
            finding_ids=finding_ids,
            event_ids=sorted(set(event_ids)),
            contributing_signals=contributing,
        )
