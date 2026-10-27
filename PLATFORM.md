# Aegis HealthSec Investigation Platform (Milestone C)

End-to-end security investigation workflow built on the existing detection
engine. This document describes what is implemented and verified. It makes no
production-readiness or HIPAA-compliance claim.

## Workflow

```
POST /api/v1/events (authenticated, org-scoped)
        │  normalize -> SecurityEvent (UTC, pseudonymous, dedup_key)
        ▼
  upsert_event (idempotent, PostgreSQL)
        │
        ▼
  PatientAccessDetector (real detection rules)  ── findings ──▶ detection_findings
        │
        ▼
  CorrelationEngine (deterministic, by identity/resource/org/time-window)
        │  idempotent correlation_key, severity = max of group
        ▼
  upsert_incident + link findings/events (PostgreSQL)
        │
        ▼
  Investigation API: assign / note / status (state machine) / disposition / close
        │  every change -> InvestigationAction (durable audit)
        ▼
  React SOC dashboard (Overview / Incident Queue / Investigation)
```

## Components (all under `detection_engine/platform/`)

| Module | Responsibility |
|---|---|
| `models.py` | Versioned pydantic models: `SecurityEvent`, `DetectionFindingRecord` (adapter over the engine's `DetectionFinding`), `SecurityIncident`, `InvestigationAction`. |
| `db.py` | SQLAlchemy 2.x ORM (8 tables), engine/session factory, `AEGIS_DATABASE_URL`. |
| `migrations/` | Alembic; initial revision creates the full schema. |
| `repository.py` | Transaction-safe, org-scoped CRUD; idempotent event/incident upserts; optimistic concurrency. |
| `correlation.py` | Deterministic correlation into incidents. |
| `ingestion.py` | Orchestrates normalize → persist → detect → correlate → persist incident. |
| `investigation.py` | Incident status state machine + auditable analyst actions + timeline. |
| `auth.py` | bcrypt password hashing, JWT (jose), roles, org-scoped `Principal`. |
| `api.py` | FastAPI app; authenticated, org-scoped endpoints. |
| `bootstrap.py` / `server.py` | App builder (cached ATT&CK index), user seeding, ASGI entrypoint. |

## Database schema (PostgreSQL)

Tables: `users`, `security_events`, `detection_findings`, `incidents`,
`incident_findings`, `incident_events`, `investigation_actions`,
`rule_versions`. Primary/foreign keys, indexes, and idempotency UNIQUE
constraints (`uq_event_org_dedup`, `uq_incident_org_corr`). Incidents carry a
`row_version` for optimistic concurrency. Schema is applied via Alembic
(`alembic upgrade head`).

## API routes

| Method | Path | Auth / role |
|---|---|---|
| GET | `/health` | none |
| GET | `/readiness` | none (503 if DB down) |
| POST | `/api/v1/auth/token` | credentials → JWT |
| POST | `/api/v1/events` | analyst/admin (ingest) |
| GET | `/api/v1/incidents` | any role (org-scoped, filter/paginate) |
| GET | `/api/v1/incidents/{id}` | any role (404 cross-org) |
| GET | `/api/v1/incidents/{id}/evidence` | any role |
| GET | `/api/v1/incidents/{id}/timeline` | any role |
| GET | `/api/v1/incidents/{id}/history` | any role |
| GET | `/api/v1/incidents/{id}/export` | any role |
| POST | `/api/v1/incidents/{id}/assign` | analyst/admin |
| POST | `/api/v1/incidents/{id}/notes` | analyst/admin |
| PATCH | `/api/v1/incidents/{id}` (status) | analyst/admin |
| POST | `/api/v1/incidents/{id}/disposition` | analyst/admin |
| POST | `/api/v1/incidents/{id}/close` | analyst/admin |

OpenAPI docs are served at `/docs` by FastAPI.

## Security controls (implemented + tested)

- Server-side JWT auth; **no unauthenticated data endpoints**.
- RBAC: `administrator`, `security_analyst`, `read_only_auditor`. Auditors
  cannot write (403, tested).
- Organization isolation on every query; cross-org access returns 404 (tested).
- Optimistic concurrency prevents lost incident updates (tested).
- Incident state changes only via legal transitions (tested); every change is
  an auditable `InvestigationAction`.
- Evidence carries pseudonymous identifiers and metadata only — no clinical
  record content; no tokens/passwords logged.
- Ingestion: idempotent dedup, batch/size limits, invalid events rejected and
  counted (not silently dropped).

## Deployment (Docker Compose)

```bash
export AEGIS_JWT_SECRET=$(openssl rand -hex 32)
export AEGIS_ADMIN_USER=admin AEGIS_ADMIN_PASSWORD=choose-a-password
docker compose -f deploy/docker-compose.yml up --build
# API:       http://localhost:8000  (/docs for OpenAPI)
# Dashboard: http://localhost:8080
```

The backend waits for a healthy PostgreSQL, applies Alembic migrations, then
serves. The frontend (nginx) serves the SPA and proxies `/api`, `/readiness`,
`/health` to the backend. PostgreSQL uses a durable named volume.

## Verified evidence (2026-10-27, isolated venv + real PostgreSQL + real Docker)

- Full test suite: **212 passed** (healthcare, automotive, firmware, ARM, ATT&CK,
  and platform including real-PostgreSQL integration and 8 real end-to-end
  API/security tests). `ruff 0.8.4`: clean. Frontend `npm run build`: succeeds.
- Automated end-to-end acceptance (`tests/test_platform_api_e2e.py`): ingest 40
  synthetic events → detect → correlate → persist incident → authenticate →
  assign/note/status/disposition → resolve → close → **restart** (fresh app) →
  incident + full audit trail preserved. Benign control produces no HIGH/CRITICAL.
- Live Docker Compose run: full stack healthy; seeded admin login; containerized
  ingest of 40 synthetic events → 1 finding → 1 HIGH incident persisted and
  retrieved; incident survived a genuine container stop/start (durable volume).

## Known limitations / not claimed

- Deterministic rules only; no ML scoring or trained anomaly model.
- Single correlation strategy (identity/resource/time-window); no cross-batch
  streaming correlation beyond persisted idempotent upserts.
- Hosted GitHub Actions CI is **BLOCKED**: repository Actions are disabled, so
  no hosted CI run can execute. All evidence above is from local/containerized
  runs. See the final report.
- No TLS termination inside the compose stack (expected to sit behind a TLS
  proxy); no production secret manager integration.
- **No HIPAA certification, no production-readiness claim, no real-world
  detection-efficacy claim.** MIMIC-IV Demo provides de-identified clinical
  context only; all security events are clearly-labeled synthetic.
