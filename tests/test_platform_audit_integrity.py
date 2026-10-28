"""Phase 6: database integrity + tamper-evident audit chain (real PostgreSQL)."""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

TEST_DB_URL = os.environ.get(
    "AEGIS_TEST_DATABASE_URL", "postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
)
os.environ.setdefault("AEGIS_DATABASE_URL", TEST_DB_URL)


def _pg() -> bool:
    try:
        from sqlalchemy import text

        from detection_engine.platform import db as _db

        e = _db.make_engine(TEST_DB_URL)
        with e.connect() as c:
            c.execute(text("SELECT 1"))
        e.dispose()
        return True
    except Exception:
        return False


from detection_engine.platform import db as _db  # noqa: E402
from detection_engine.platform.models import (  # noqa: E402
    IncidentSeverity,
    InvestigationAction,
    InvestigationActionType,
    SecurityIncident,
)
from detection_engine.platform.repository import Repository  # noqa: E402

pytestmark = pytest.mark.skipif(not _pg(), reason="requires PostgreSQL")


def _incident(repo, org="org-a", key="K1"):
    inc = SecurityIncident(title="t", severity=IncidentSeverity.HIGH,
                           organization_id=org, correlation_key=key)
    row, _ = repo.upsert_incident(inc)
    return row


def _action(repo, incident_id, org="org-a", atype=InvestigationActionType.ADD_NOTE, note="n", analyst="a1", ts_min=0):
    return repo.add_action(InvestigationAction(
        incident_id=incident_id, analyst_id=analyst, action_type=atype,
        note=note, organization_id=org,
        timestamp=datetime(2026, 10, 27, 10, ts_min, tzinfo=timezone.utc),
    ))


class TestAuditHashChain:
    def test_chain_builds_and_verifies(self, pg_session):
        repo = Repository(pg_session)
        inc = _incident(repo)
        for i in range(5):
            _action(repo, inc.incident_id, ts_min=i, note=f"note-{i}")
        pg_session.commit()
        assert repo.verify_audit_chain("org-a") is True

    def test_tamper_note_breaks_chain(self, pg_session):
        repo = Repository(pg_session)
        inc = _incident(repo)
        rows = [_action(repo, inc.incident_id, ts_min=i) for i in range(4)]
        pg_session.commit()
        assert repo.verify_audit_chain("org-a") is True
        # Tamper: alter a persisted note WITHOUT recomputing the chain.
        target = pg_session.get(_db.InvestigationActionRow, rows[1].action_id)
        target.note = "tampered-after-the-fact"
        pg_session.commit()
        assert repo.verify_audit_chain("org-a") is False  # detected

    def test_tamper_delete_breaks_chain(self, pg_session):
        repo = Repository(pg_session)
        inc = _incident(repo)
        rows = [_action(repo, inc.incident_id, ts_min=i) for i in range(4)]
        pg_session.commit()
        # Delete a middle audit row -> sequence gap -> chain fails.
        pg_session.delete(pg_session.get(_db.InvestigationActionRow, rows[1].action_id))
        pg_session.commit()
        assert repo.verify_audit_chain("org-a") is False

    def test_chain_is_per_org(self, pg_session):
        repo = Repository(pg_session)
        inc_a = _incident(repo, org="org-a", key="A")
        inc_b = _incident(repo, org="org-b", key="B")
        _action(repo, inc_a.incident_id, org="org-a")
        _action(repo, inc_b.incident_id, org="org-b")
        pg_session.commit()
        assert repo.verify_audit_chain("org-a") is True
        assert repo.verify_audit_chain("org-b") is True

    def test_chain_survives_restart(self, pg_engine):
        # Build chain with one session, then verify with a fresh engine/session.
        s1 = _db.make_session_factory(pg_engine)()
        repo = Repository(s1)
        inc = _incident(repo)
        for i in range(3):
            _action(repo, inc.incident_id, ts_min=i)
        s1.commit()
        s1.close()
        pg_engine.dispose()
        e2 = _db.make_engine(TEST_DB_URL)
        try:
            s2 = _db.make_session_factory(e2)()
            assert Repository(s2).verify_audit_chain("org-a") is True
            s2.close()
        finally:
            e2.dispose()


class TestTransactionalIntegrity:
    def test_rollback_discards_partial_writes(self, pg_session):
        repo = Repository(pg_session)
        inc = _incident(repo)
        _action(repo, inc.incident_id)
        # Roll back before commit: nothing persists.
        pg_session.rollback()
        # Fresh repo/session sees no incident or actions.
        s2 = _db.make_session_factory(pg_session.get_bind())()
        assert Repository(s2).get_incident(inc.incident_id, "org-a") is None
        s2.close()

    def test_concurrent_analyst_updates_optimistic_lock(self, pg_engine):
        from detection_engine.platform.repository import ConcurrencyError

        s = _db.make_session_factory(pg_engine)()
        repo = Repository(s)
        inc = _incident(repo)
        s.commit()
        # Two independent sessions read the same version.
        sA = _db.make_session_factory(pg_engine)()
        sB = _db.make_session_factory(pg_engine)()
        rA, rB = Repository(sA), Repository(sB)
        vA = rA.get_incident(inc.incident_id, "org-a").row_version
        vB = rB.get_incident(inc.incident_id, "org-a").row_version
        rA.update_incident(inc.incident_id, "org-a", expected_version=vA, status="TRIAGED")
        sA.commit()
        # B's stale-version write must be rejected (no silent lost update).
        with pytest.raises(ConcurrencyError):
            rB.update_incident(inc.incident_id, "org-a", expected_version=vB, status="CLOSED")
        sA.close()
        sB.close()
        s.close()

    def test_duplicate_incident_retry_no_duplicate(self, pg_session):
        repo = Repository(pg_session)
        _incident(repo, key="DUP")
        _incident(repo, key="DUP")  # same correlation_key -> idempotent
        pg_session.commit()
        rows = pg_session.query(_db.IncidentRow).filter_by(organization_id="org-a").all()
        assert len(rows) == 1
