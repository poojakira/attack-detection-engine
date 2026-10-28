# Milestone C — Phase 0 Baseline Verification (2026-10-27)

Branch: `feat/milestone-c-platform` (forked from `feat/healthsec-detection`).
Additive record; preserves all prior snapshots.

## Reproduced baseline (not assumed)

Isolated venv, pinned `attack-v19-core@087accffc7`, Python 3.12.3:

- `pytest` → **116 passed** (70 original + 46 healthcare). Reproduced, not assumed.
- `ruff 0.8.4 check` → All checks passed.
- Healthcare increments present: schema, synthetic generator, PatientAccessDetector
  (7 rules), MIMIC-IV adapter, pipeline `clinical_access` source.
- Automotive / firmware / ARM / ATT&CK detectors present and passing.
- Pinned dependency confirmed: `attack-v19-core` commit
  `087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b`.

## Environment available for genuine verification

| Tool | Version | Use |
|---|---|---|
| PostgreSQL | 15.17, accepting connections on `/var/run/postgresql:5432` | real DB integration tests |
| Docker | 29.3.0 | Compose deployment |
| Node / npm | v20.10.0 / 10.2.3 | frontend build |
| FastAPI | 0.111.0 (compatible with pinned pydantic 2.7.4) | ingestion + investigation API |
| SQLAlchemy / Alembic | 2.1.6 / (installed) | persistence + migrations |
| psycopg | 3.x binary | Postgres driver |

## Dependency decision (documented)

`fastapi>=0.162` requires `pydantic>=2.9`, which conflicts with the engine's
pinned `pydantic==2.7.4` (required by `attack-v19-core`). To preserve the pinned
core contract, FastAPI is pinned to **0.111.0** (supports pydantic 2.7.x). Core
baseline re-verified at **116 passed** with these versions installed.

## Known blocker (reported, not worked around)

Hosted GitHub Actions on this account do not get a runner assigned: dispatched
`ci.yml` run `40562530813` stayed `queued` with 0 jobs. This matches the repo's
previously documented hosted-runner limitation. Local gates are the source of
truth in this environment.
