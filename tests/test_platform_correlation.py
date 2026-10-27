"""Tests for the deterministic correlation engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from detection_engine.platform.correlation import (
    CorrelationConfig,
    CorrelationEngine,
)
from detection_engine.platform.models import DetectionFindingRecord, IncidentSeverity

T0 = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)


def _f(rule_id, severity, identity="clin-1", resource="res-1", org="org-a",
       minutes=0, confidence=0.8, techniques=None):
    return DetectionFindingRecord(
        rule_id=rule_id,
        severity=IncidentSeverity(severity),
        confidence=confidence,
        affected_identity=identity,
        affected_resource=resource,
        organization_id=org,
        detection_timestamp=T0 + timedelta(minutes=minutes),
        mapped_attack_techniques=techniques or [],
    )


class TestScenarioA_SuspiciousHealthcareAccess:
    def test_denied_then_success_plus_bulk_correlate(self):
        findings = [
            _f("HC-ACCESS-DENYSUCCESS", "HIGH", minutes=1),
            _f("HC-ACCESS-BULK", "HIGH", minutes=2),
            _f("HC-EXFIL-BULKEXPORT", "CRITICAL", minutes=3, techniques=["T1567"]),
        ]
        incidents = CorrelationEngine().correlate(findings)
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc.incident.severity == IncidentSeverity.CRITICAL  # escalated
        assert len(inc.finding_ids) == 3
        assert "T1567" in inc.incident.affected_entities["attack_techniques"]
        # explainable
        assert "Signals" in inc.incident.correlation_reason


class TestScenarioB_PrivilegeAbuse:
    def test_identity_findings_group(self):
        findings = [
            _f("HC-IDENTITY-SVCSCOPE", "HIGH", identity="svc-1", minutes=1),
            _f("HC-ACCESS-UNASSIGNED", "MEDIUM", identity="svc-1", minutes=5),
        ]
        incidents = CorrelationEngine().correlate(findings)
        assert len(incidents) == 1
        assert incidents[0].incident.severity == IncidentSeverity.HIGH


class TestScenarioC_AuditSuppression:
    def test_audit_category_label(self):
        findings = [_f("HC-AUDIT-DISABLED", "HIGH", identity="admin-1")]
        incidents = CorrelationEngine().correlate(findings)
        assert len(incidents) == 1
        assert "audit" in incidents[0].incident.correlation_key


class TestScenarioD_BenignControl:
    def test_no_findings_no_incident(self):
        assert CorrelationEngine().correlate([]) == []


class TestNegativesAndIsolation:
    def test_unrelated_identities_not_merged(self):
        findings = [
            _f("HC-ACCESS-BULK", "HIGH", identity="clin-1", minutes=1),
            _f("HC-ACCESS-BULK", "HIGH", identity="clin-2", minutes=2),
        ]
        incidents = CorrelationEngine().correlate(findings)
        assert len(incidents) == 2

    def test_separate_orgs_not_merged(self):
        findings = [
            _f("HC-ACCESS-BULK", "HIGH", identity="clin-1", org="org-a", minutes=1),
            _f("HC-ACCESS-BULK", "HIGH", identity="clin-1", org="org-b", minutes=2),
        ]
        incidents = CorrelationEngine().correlate(findings)
        assert len(incidents) == 2
        assert {i.incident.organization_id for i in incidents} == {"org-a", "org-b"}


class TestTimeWindows:
    def test_findings_outside_window_separate(self):
        cfg = CorrelationConfig(time_window=timedelta(minutes=10))
        findings = [
            _f("HC-ACCESS-BULK", "HIGH", minutes=1),
            _f("HC-ACCESS-BULK", "HIGH", minutes=90),  # far outside window
        ]
        incidents = CorrelationEngine(cfg).correlate(findings)
        assert len(incidents) == 2

    def test_findings_inside_window_merge(self):
        cfg = CorrelationConfig(time_window=timedelta(hours=2))
        findings = [
            _f("HC-ACCESS-BULK", "HIGH", minutes=1),
            _f("HC-ACCESS-DENYSUCCESS", "HIGH", minutes=30),
        ]
        incidents = CorrelationEngine(cfg).correlate(findings)
        assert len(incidents) == 1


class TestIdempotencyAndEscalation:
    def test_correlation_key_stable_and_order_independent(self):
        a = [_f("HC-ACCESS-BULK", "HIGH", minutes=1), _f("HC-EXFIL-BULKEXPORT", "CRITICAL", minutes=2)]
        b = list(reversed(a))
        ka = CorrelationEngine().correlate(a)[0].incident.correlation_key
        kb = CorrelationEngine().correlate(b)[0].incident.correlation_key
        assert ka == kb

    def test_severity_is_max_of_group(self):
        findings = [
            _f("HC-ACCESS-UNASSIGNED", "LOW", minutes=1),
            _f("HC-ACCESS-BULK", "MEDIUM", minutes=2),
            _f("HC-EXFIL-BULKEXPORT", "CRITICAL", minutes=3),
        ]
        inc = CorrelationEngine().correlate(findings)[0]
        assert inc.incident.severity == IncidentSeverity.CRITICAL

    def test_event_ids_attached_from_mapping(self):
        f1 = _f("HC-ACCESS-BULK", "HIGH", minutes=1)
        incidents = CorrelationEngine().correlate(
            [f1], event_ids_by_finding={f1.finding_id: ["evt-1", "evt-2"]}
        )
        assert incidents[0].event_ids == ["evt-1", "evt-2"]
