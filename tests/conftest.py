"""Reuse the expensive, immutable ATT&CK STIX index across integration tests.

The ``attack_v19_core`` import is performed lazily inside the fixture so that
tests which do not require the ATT&CK index (e.g. the offline automotive /
firmware / ARM-ELF tests) can still be collected and run in environments where
``attack_v19_core`` is not installed. Tests that request ``attack_index`` are
skipped with a clear message when the package is unavailable.
"""

import pytest


@pytest.fixture(scope="session")
def attack_index():
    try:
        from attack_v19_core import ATTACKLoader, ATTACKIndex
    except ImportError:
        pytest.skip("attack_v19_core is not installed")
    return ATTACKIndex(ATTACKLoader())


# --- Platform PostgreSQL integration fixtures -------------------------------

import os  # noqa: E402

TEST_DB_URL = os.environ.get(
    "AEGIS_TEST_DATABASE_URL", "postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
)


def _postgres_available() -> bool:
    try:
        from sqlalchemy import text

        from detection_engine.platform import db as _db

        engine = _db.make_engine(TEST_DB_URL)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        engine.dispose()
        return True
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(
    not _postgres_available(),
    reason=f"PostgreSQL not reachable at {TEST_DB_URL}",
)


@pytest.fixture()
def pg_engine():
    from detection_engine.platform import db as _db

    engine = _db.make_engine(TEST_DB_URL)
    _db.Base.metadata.drop_all(engine)
    _db.Base.metadata.create_all(engine)
    yield engine
    _db.Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture()
def pg_session(pg_engine):
    from detection_engine.platform import db as _db

    factory = _db.make_session_factory(pg_engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
