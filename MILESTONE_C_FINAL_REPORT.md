# Milestone C — Final Delivery Report (2026-10-27)

Branch: `feat/milestone-c-platform` (forked from `feat/healthsec-detection`).
All results below were reproduced in this environment; blockers are stated, not
worked around.

## A. Implemented components (with source references)

| Capability | Source |
|---|---|
| Investigation data model | `detection_engine/platform/models.py` |
| PostgreSQL persistence (SQLAlchemy 2.x) | `detection_engine/platform/db.py` |
| Alembic migrations | `detection_engine/platform/migrations/` (rev `4295fbcefb96`) |
| Repository (idempotent, org-scoped, concurrency) | `detection_engine/platform/repository.py` |
| Deterministic correlation engine | `detection_engine/platform/correlation.py` |
| Ingestion orchestration | `detection_engine/platform/ingestion.py` |
| Incident state machine + audit + timeline | `detection_engine/platform/investigation.py` |
| Auth (bcrypt + JWT) + RBAC | `detection_engine/platform/auth.py` |
| FastAPI API | `detection_engine/platform/api.py` |
| ASGI entrypoint + bootstrap | `detection_engine/platform/server.py`, `bootstrap.py` |
| React/TS SOC dashboard | `dashboard-ui/` |
| Docker Compose deployment | `deploy/` |

## B. Architecture

See `PLATFORM.md` for the data-flow diagram and component table. Summary:
`POST /api/v1/events` → normalize to `SecurityEvent` → idempotent persist →
`PatientAccessDetector` → `CorrelationEngine` → idempotent `SecurityIncident`
→ investigation API (state machine + `InvestigationAction` audit) → React
dashboard.

## C. Database tables & migrations

`users`, `security_events`, `detection_findings`, `incidents`,
`incident_findings`, `incident_events`, `investigation_actions`,
`rule_versions`. PK/FK, indexes, idempotency UNIQUE constraints, `row_version`
optimistic concurrency. Applied via `alembic upgrade head` (verified against
real PostgreSQL 15).

## D. Real API endpoints

15 routes (see `PLATFORM.md` table). OpenAPI at `/docs`.

## E. Detection & correlation

Reuses the existing `PatientAccessDetector` (7 deterministic rules). Correlation
groups by organization + identity/resource + time window; idempotent
`correlation_key`; severity = max of contributing findings; ATT&CK attached only
for exfil-shaped findings (T1567). No ML, no invented mappings.

## F. Security testing (exact commands + results)

Environment: isolated venv, pinned `attack-v19-core@087accffc7`, Python 3.12.3,
real PostgreSQL 15 (Docker `aegis-pg` @127.0.0.1:55432).

```bash
. .venv/bin/activate
export AEGIS_DATABASE_URL="postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
export AEGIS_JWT_SECRET="gate-secret"
ruff check detection_engine tests scripts .github/scripts        # All checks passed
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH= python -m pytest -q  # 212 passed
( cd dashboard-ui && npm run build )                             # built OK
```

- **212 passed**, 0 failed. Includes real-PostgreSQL integration
  (`tests/test_platform_db.py`, 11) and real end-to-end API/security tests
  (`tests/test_platform_api_e2e.py`, 8): full investigation workflow +
  restart persistence, benign control, unauthenticated rejection, cross-org
  isolation, auditor RBAC, duplicate dedup, invalid-event rejection, invalid
  status transition.
- Second review: no token/password/secret logging; no secrets/dataset/artifacts
  committed; all write endpoints role-gated; cross-org → 404.

## G. Deployment (verified on real Docker)

```bash
export AEGIS_JWT_SECRET=$(openssl rand -hex 32)
export AEGIS_ADMIN_USER=admin AEGIS_ADMIN_PASSWORD=<pw>
docker compose -f deploy/docker-compose.yml up --build
```

Observed: all three services healthy; seeded admin login; containerized ingest
of 40 synthetic events → 1 finding → 1 HIGH incident persisted and retrieved via
the API; frontend served the SPA and proxied `/readiness`; the incident survived
a genuine container stop/start (durable volume). A missing ATT&CK bundle first
surfaced as an honest 500 (not false-healthy) and was fixed by baking the bundle
into the backend image.

## H. Documentation updated

`README.md` (platform section), `PLATFORM.md` (new), `PRODUCTION.md`,
`RUNBOOK.md`, `MILESTONE_C_BASELINE_2026-10-27.md` (new), this report. Prior
dated snapshots and healthcare/automotive docs preserved unchanged.

## I. Known gaps / not claimed

- Deterministic rules only; no ML detection or accuracy metric.
- Single correlation strategy; no streaming cross-batch correlation beyond
  idempotent persisted upserts.
- No TLS inside the compose stack (expected behind a TLS proxy); no external
  secret-manager integration.
- **No HIPAA certification, no production-readiness claim, no real-world
  detection-efficacy claim.** MIMIC-IV Demo = de-identified clinical context
  only; all security events are clearly-labeled synthetic; a MIMIC admission
  link is a care relationship, not access authorization.

## J. GitHub delivery & CI status

- Branch: `feat/milestone-c-platform`. Commits (this milestone):
  `f862984` per-function tests, `b4ca18a` data model, `be788bc` persistence,
  `32be5af` correlation, `9f318b3` API/auth/e2e, `805e12c` dashboard,
  `0553ea6` deploy, plus this documentation commit.
- PR #47 (`feat/healthsec-detection` → `main`) remains **open and unmerged**.
- **CI status: BLOCKED.** `GET repos/poojakira/attack-detection-engine/actions/permissions`
  returns `enabled=false` — GitHub Actions is disabled at the repository level,
  so dispatched workflows stay `queued` with zero jobs and cannot execute. This
  is a repository setting (Settings → Actions), not a code or billing issue. To
  unblock: enable Actions, then re-run CI. Until then, the authoritative
  evidence is the local + containerized runs recorded above. A queued workflow
  is neither a pass nor a fail.

## Acceptance statement

The primary acceptance test — an authorized analyst ingesting, investigating,
documenting, and resolving a real **persisted** security incident through the
functioning API (and its survival across restart) — **passes** in this
environment, verified by `tests/test_platform_api_e2e.py` and a live Docker
Compose run. Production readiness is explicitly **not** claimed.
