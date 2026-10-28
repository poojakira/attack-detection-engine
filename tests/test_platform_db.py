"""Real PostgreSQL integration tests for the persistence layer.

Requires a reachable PostgreSQL (see conftest ``requires_postgres``). These
tests exercise idempotent writes, foreign-key integrity, optimistic-concurrency
updates, filtered pagination, and — critically — persistence across a simulated
application restart (dispose the engine, build a fresh one, confirm data).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from detection_engine.platform import db as _db
from detection_engine.platform.models import (
    DataOrigin,
    DetectionFindingRecord,
    IncidentSeverity,
    IncidentStatus,
    InvestigationAction,
    InvestigationActionType,
    SecurityEvent,
    SecurityIncident,
)
from detection_engine.platform.repository import ConcurrencyError, Repository

TEST_DB_URL = os.environ.get(
    "AEGIS_TEST_DATABASE_URL", "postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
)


def _postgres_available() -> bool:
    try:
        from sqlalchemy import text

        engine = _db.make_engine(TEST_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_available(), reason=f"PostgreSQL not reachable at {TEST_DB_URL}"
)


def _event(**kw):
    base = dict(
        source_type="clinical_access",
        event_timestamp=datetime(2026, 10, 27, 10, tzinfo=timezone.utc),
        organization_id="org-a",
        data_origin=DataOrigin.SYNTHETIC,
    )
    base.update(kw)
    return SecurityEvent(**base)


class TestEventPersistence:
    def test_insert_and_read_event(self, pg_session):
        repo = Repository(pg_session)
        row, created = repo.upsert_event(_event(source_event_id="S1"))
        pg_session.commit()
        assert created is True
        got = repo.get_event(row.event_id, "org-a")
        assert got is not None and got.source_type == "clinical_access"

    def test_idempotent_event_dedup(self, pg_session):
        repo = Repository(pg_session)
        e = _event(source_event_id="S1")
        _, c1 = repo.upsert_event(e)
        pg_session.commit()
        # Same source_event_id + org -> no duplicate
        _, c2 = repo.upsert_event(_event(source_event_id="S1"))
        pg_session.commit()
        assert c1 is True and c2 is False
        total = len(
            pg_session.query(_db.SecurityEventRow).filter_by(organization_id="org-a").all()
        )
        assert total == 1

    def test_distinct_orgs_not_deduped(self, pg_session):
        repo = Repository(pg_session)
        repo.upsert_event(_event(source_event_id="S1", organization_id="org-a"))
        repo.upsert_event(_event(source_event_id="S1", organization_id="org-b"))
        pg_session.commit()
        assert len(pg_session.query(_db.SecurityEventRow).all()) == 2


class TestIncidentPersistence:
    def _finding(self, repo, org="org-a"):
        rec = DetectionFindingRecord(
            rule_id="HC-ACCESS-BULK",
            severity=IncidentSeverity.HIGH,
            confidence=0.8,
            organization_id=org,
        )
        repo.add_finding(rec)
        return rec

    def test_incident_with_links_and_fk(self, pg_session):
        repo = Repository(pg_session)
        ev, _ = repo.upsert_event(_event(source_event_id="S1"))
        fnd = self._finding(repo)
        inc = SecurityIncident(
            title="Suspicious access",
            severity=IncidentSeverity.HIGH,
            organization_id="org-a",
            correlation_key="org-a|clin-1|bulk",
        )
        row, created = repo.upsert_incident(inc, finding_ids=[fnd.finding_id], event_ids=[ev.event_id])
        pg_session.commit()
        assert created is True
        assert len(repo.incident_findings(row.incident_id)) == 1
        assert len(repo.incident_events(row.incident_id)) == 1

    def test_idempotent_incident_by_correlation_key(self, pg_session):
        repo = Repository(pg_session)
        inc = SecurityIncident(
            title="t", severity=IncidentSeverity.MEDIUM,
            organization_id="org-a", correlation_key="K1",
            last_seen=datetime(2026, 10, 27, 10, tzinfo=timezone.utc),
        )
        _, c1 = repo.upsert_incident(inc)
        pg_session.commit()
        # Repeat correlation key with higher severity -> escalate, no duplicate
        inc2 = SecurityIncident(
            title="t", severity=IncidentSeverity.CRITICAL,
            organization_id="org-a", correlation_key="K1",
            last_seen=datetime(2026, 10, 27, 12, tzinfo=timezone.utc),
        )
        row2, c2 = repo.upsert_incident(inc2)
        pg_session.commit()
        assert c1 is True and c2 is False
        assert len(pg_session.query(_db.IncidentRow).all()) == 1
        assert row2.severity == "CRITICAL"  # escalated

    def test_optimistic_concurrency(self, pg_session):
        repo = Repository(pg_session)
        inc = SecurityIncident(title="t", severity=IncidentSeverity.LOW, organization_id="org-a", correlation_key="C1")
        row, _ = repo.upsert_incident(inc)
        pg_session.commit()
        # Correct version succeeds
        repo.update_incident(row.incident_id, "org-a", expected_version=1, status="TRIAGED")
        pg_session.commit()
        # Stale version raises
        with pytest.raises(ConcurrencyError):
            repo.update_incident(row.incident_id, "org-a", expected_version=1, status="CLOSED")

    def test_cross_org_isolation_on_read(self, pg_session):
        repo = Repository(pg_session)
        inc = SecurityIncident(title="t", severity=IncidentSeverity.LOW, organization_id="org-a", correlation_key="C2")
        row, _ = repo.upsert_incident(inc)
        pg_session.commit()
        # Another org cannot read it
        assert repo.get_incident(row.incident_id, "org-b") is None
        assert repo.get_incident(row.incident_id, "org-a") is not None

    def test_list_incidents_filter_and_paginate(self, pg_session):
        repo = Repository(pg_session)
        for i in range(5):
            repo.upsert_incident(SecurityIncident(
                title=f"t{i}", severity=IncidentSeverity.HIGH,
                status=IncidentStatus.NEW, organization_id="org-a",
                correlation_key=f"P{i}",
                created_at=datetime(2026, 10, 27, 10, i, tzinfo=timezone.utc),
            ))
        pg_session.commit()
        rows, total = repo.list_incidents("org-a", status="NEW", limit=2, offset=0)
        assert total == 5 and len(rows) == 2


class TestInvestigationAudit:
    def test_action_recorded_and_ordered(self, pg_session):
        repo = Repository(pg_session)
        inc = SecurityIncident(title="t", severity=IncidentSeverity.HIGH, organization_id="org-a", correlation_key="A1")
        row, _ = repo.upsert_incident(inc)
        pg_session.commit()
        for i, atype in enumerate([InvestigationActionType.ACKNOWLEDGE, InvestigationActionType.ADD_NOTE]):
            repo.add_action(InvestigationAction(
                incident_id=row.incident_id, analyst_id="analyst-1",
                action_type=atype, note=f"n{i}",
                timestamp=datetime(2026, 10, 27, 10, i, tzinfo=timezone.utc),
                organization_id="org-a",
            ))
        pg_session.commit()
        actions = repo.incident_actions(row.incident_id)
        assert [a.action_type for a in actions] == ["acknowledge", "add_note"]


class TestCorrelationPersistenceIdempotency:
    def test_rerun_correlation_does_not_duplicate_incident(self, pg_session):
        from detection_engine.platform.correlation import CorrelationEngine

        repo = Repository(pg_session)
        # Two findings for same identity -> one correlated incident
        findings = []
        for rid, sev in [("HC-ACCESS-BULK", IncidentSeverity.HIGH),
                         ("HC-EXFIL-BULKEXPORT", IncidentSeverity.CRITICAL)]:
            rec = DetectionFindingRecord(
                rule_id=rid, severity=sev, confidence=0.8,
                affected_identity="clin-9", affected_resource="res-1",
                organization_id="org-a",
                detection_timestamp=datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc),
            )
            repo.add_finding(rec)
            findings.append(rec)
        pg_session.commit()

        engine = CorrelationEngine()
        # First correlation run -> create
        for ci in engine.correlate(findings):
            repo.upsert_incident(ci.incident, finding_ids=ci.finding_ids)
        pg_session.commit()
        # Second identical run -> must NOT duplicate (same correlation_key)
        for ci in engine.correlate(findings):
            repo.upsert_incident(ci.incident, finding_ids=ci.finding_ids)
        pg_session.commit()

        incidents = pg_session.query(_db.IncidentRow).filter_by(organization_id="org-a").all()
        assert len(incidents) == 1
        assert incidents[0].severity == "CRITICAL"
        assert len(repo.incident_findings(incidents[0].incident_id)) == 2


class TestRestartPersistence:
    def test_data_survives_engine_restart(self, pg_engine):
        # Write with one engine/session, dispose, then read with a fresh engine.
        factory = _db.make_session_factory(pg_engine)
        s1 = factory()
        repo = Repository(s1)
        ev, _ = repo.upsert_event(_event(source_event_id="S-RESTART"))
        inc = SecurityIncident(
            title="persisted", severity=IncidentSeverity.HIGH,
            organization_id="org-a", correlation_key="RESTART",
        )
        inc_row, _ = repo.upsert_incident(inc, event_ids=[ev.event_id])
        incident_id = inc_row.incident_id
        s1.commit()
        s1.close()
        pg_engine.dispose()  # simulate application shutdown

        # Fresh engine + session (simulated restart) against the same database.
        engine2 = _db.make_engine(TEST_DB_URL)
        try:
            s2 = _db.make_session_factory(engine2)()
            repo2 = Repository(s2)
            got = repo2.get_incident(incident_id, "org-a")
            assert got is not None
            assert got.title == "persisted"
            assert len(repo2.incident_events(incident_id)) == 1
            s2.close()
        finally:
            engine2.dispose()
