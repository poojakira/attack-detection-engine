# Production Operating Contract

## System role

This repository is maintained as a **security event detection engine**.

## Production purpose

normalize inputs and execute deterministic rule/detector pipelines with machine-readable findings.

## Release gate

A release is promotable only when pipeline/CLI tests, rule validation, container build, lint, and dependency/security gates pass.

## Operating requirements

- Configuration must come from explicit environment/config files; secrets must never be committed.
- Production defaults must fail safely when required identity, credentials, artifacts, or dependencies are missing.
- Health/readiness behavior must represent real dependency state where the repository exposes a service.
- Logs and machine-readable outputs must support incident/debug reconstruction without leaking secrets.
- Dependency and security findings at the repository's blocking threshold must stop promotion.
- Public metrics and benchmark claims must identify their dataset, environment, and scope.
- Deployment images/artifacts must be versioned and immutable at promotion time.
- Rollback must be possible without rewriting Git history.

## Evidence boundary

"Production-oriented" describes the engineering and release contract of this repository. It does **not** mean that an external enterprise deployment, penetration test, certification, uptime history, or scale target has occurred unless a separate committed artifact proves it.

## Change management

Main is the supported integration branch. Production changes should be small, reviewable, tested, and tied to observable behavior. Historical benchmark/research material may remain for evidence, but active README, security, runbook, and deployment surfaces must describe the supported runtime rather than an academic or prototype status.


## Automotive and embedded-security scope update (October 15, 2026)

The repository also accepts `automotive_can`, `firmware`, and `arm_binary`
offline inputs through `DetectionPipeline`. Verified scope is limited to
synthetic CAN trace parsing and policy findings, selected C/C++ CWE-pattern
candidate findings, and inspection of a locally cross-compiled ARM Cortex-M3
ELF32 sample. A controlled native C fixture produced a reproducible
AddressSanitizer stack-buffer-overflow finding; a separate fixed fixture
rejected the same oversized input. This is an intentionally inserted lab
vulnerability, not a discovery in a production ECU.

For exact sample code, compiler commands, regression tests and unsupported
claims, consult [AUTOMOTIVE_SECURITY.md](AUTOMOTIVE_SECURITY.md). This
update does not retroactively change historical snapshots and does not claim
hardware testing, live vehicle penetration testing, full firmware reverse
engineering, production efficacy, or independent security certification.
The targeted post-merge Windows Python 3.12 run passed 29 tests; a later
Python 3.11 Docker run (October 17, 2026) with two added ARM-ELF regression
tests passed 31 focused tests. Neither number is a full-repository test total.


## Milestone C: Investigation platform (October 27, 2026)

The repository now also contains an end-to-end investigation platform under
`detection_engine/platform/` (FastAPI API, PostgreSQL persistence via SQLAlchemy
+ Alembic, deterministic correlation, RBAC/auth, and a React/TS SOC dashboard
under `dashboard-ui/`). It is deployed via `deploy/docker-compose.yml`
(postgres + backend + frontend) with health/readiness checks and migration
startup.

Operating requirements specific to the platform:

- `AEGIS_JWT_SECRET` MUST be provided in any deployment; the container
  entrypoint refuses to start without it (no insecure default).
- `AEGIS_DATABASE_URL` configures PostgreSQL; the backend applies
  `alembic upgrade head` on startup and waits for a healthy database.
- `/readiness` returns 503 when the database is unreachable (no false-healthy).
- Every data endpoint requires authentication and is organization-scoped;
  cross-organization access returns 404.

Verified locally and in a real Docker Compose run on 2026-10-27: full test suite
**212 passed** (incl. real PostgreSQL integration and 8 end-to-end API/security
tests), ruff clean, frontend build succeeds, and the stack ingests → detects →
correlates → persists → investigates → resolves an incident that survives a
container restart. This is engineering/release evidence in a controlled
environment. It is **not** a claim of external enterprise deployment, HIPAA
certification, penetration test, or uptime history. Hosted GitHub Actions CI is
currently BLOCKED because repository Actions are disabled; see PLATFORM.md and
the final report.
