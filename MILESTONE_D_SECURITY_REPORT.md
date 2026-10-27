# Milestone D — Security Hardening Report (2026-10-27)

Branch: `feat/milestone-d-hardening` (off `feat/milestone-c-platform`).
Objective: harden the Aegis HealthSec investigation platform for a **controlled
pilot evaluation** — not production, not HIPAA compliance, not live ePHI.

All results reproduced locally in an isolated venv with the pinned
`attack-v19-core@087accffc7` (pydantic 2.7.4) against real PostgreSQL 15 (Docker)
and real Docker Compose. Hosted CI is BLOCKED (see Verdict).

## A. Security assessment — initial weaknesses → fixes

| # | Weakness (Milestone C) | Impact | Fix (Milestone D) | Regression test |
|---|---|---|---|---|
| 1 | Stateless JWT: role/org/disabled state never re-checked | Disabled/role-changed user keeps access until expiry | DB-backed `resolve_principal` + `token_version` revocation; `is_active` fail-closed | `test_platform_auth_hardening` disabled/token_version/role-change |
| 2 | bcrypt silently truncated passwords at 72 bytes | Auth ambiguity (distinct long passwords collide) | Argon2id (OWASP) with versioned formats; verify-then-upgrade migration | `test_...prefix_differ`, `test_legacy_hash_migrates` |
| 3 | No login rate limiting | Brute force / credential stuffing | `LoginThrottle` (user+ip lockout), generic errors, no enumeration | `TestLoginThrottle`, `test_bad_login_is_generic` |
| 4 | No iss/aud; weak claim validation | Token misuse | iss+aud+required-claim+alg-allowlist; none-alg rejected | `TestTokenValidation` |
| 5 | Default DB password; backend on 0.0.0.0 | Unauthorized DB/remote access | No default (fails closed); Postgres unpublished; localhost dev binds; non-root/read-only/cap-drop containers | compose config + real-Docker run |
| 6 | No security headers / body limit / CORS / safe errors | XSS/DoS/info-leak | Security headers, body-size limit (not trusting Content-Length), restricted CORS, generic 500 | `test_platform_web_security` |
| 7 | No tamper-evident audit | Repudiation | Per-org hash chain over `investigation_actions` + `verify_audit_chain` | `test_platform_audit_integrity` |
| 8 | Vulnerable deps (python-jose, ecdsa, old starlette) | Known CVEs | PyJWT swap (removes jose+ecdsa CVEs); FastAPI 0.116.2 / starlette 0.48.0 | `security_scans/` + suite |

## B. Implemented hardening (files)

`detection_engine/platform/auth.py` (Argon2id, JWT, revocation, throttle,
`require_secure_config`), `api.py` (DB-backed principal, security middleware,
safe errors, login throttle), `db.py` + migrations `53fef2dbf01d`,
`a1b2c3d4e5f6` (token_version, audit hash chain), `repository.py`
(`verify_audit_chain`, optimistic concurrency), `server.py` (secure-config
gate), `deploy/docker-compose.yml` + `Dockerfile.backend` + `.env.example`
(no-default-creds, non-root, read-only, unpublished DB), `THREAT_MODEL.md`.

## C. Verification (exact)

```bash
. .venv/bin/activate
export AEGIS_DATABASE_URL=postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis
export AEGIS_JWT_SECRET=<>=32 chars>
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH= python -m pytest -q   # 280 passed
ruff check detection_engine tests scripts .github/scripts          # clean
```

- **280 tests passed, 0 failed** (local, real PostgreSQL). Includes 68
  security-specific tests: auth hardening 25, tenant isolation 21, web security
  8, audit integrity 8, failure injection 6.
- Hardened Docker Compose stack **verified live**: fails closed without secrets;
  with secrets comes up healthy running non-root (uid 10001) read-only; full
  ingest→detect→correlate→persist e2e works; Postgres not published to host;
  incident survives genuine container stop/start.
- Supply chain: bandit 0 medium/high; python-jose/ecdsa CVEs eliminated; SBOM
  generated; secret scan clean (only synthetic test fixtures).

> Metric provenance: "280 tests passed in the Milestone D local regression
> suite on 2026-10-27, Python 3.12.3, real PostgreSQL 15 (Docker), pinned
> attack-v19-core@087accffc7." This is local/containerized validation, **not**
> hosted CI and **not** a production metric.

## D. Independent review (Phase 12) — findings

Adversarial testing on authorized local infrastructure (the 68 security tests
are the executable review). No unresolved critical/high findings within scope.
Confirmed-and-fixed this milestone: stateless-token privilege retention (High),
password truncation ambiguity (High), default DB password (High), missing
cross-org adversarial proof (High) — all now fail closed with regression tests.

## E. Feature / gate matrix

| Gate | Status | Evidence |
|---|---|---|
| Regression suite passes (no weakened tests) | **VERIFIED** | 280 passed |
| AuthN/JWT/Argon2id security-tested | **VERIFIED** | auth hardening 25 |
| Cross-org isolation verified (every endpoint) | **VERIFIED** | tenant isolation 21 |
| Deployment: no default creds / unneeded exposure | **VERIFIED** | compose + live run |
| End-to-end investigation workflow | **VERIFIED** | e2e 8 (Milestone C/D) |
| DB migrations + persistence | **VERIFIED** | real-PG + restart tests |
| Tamper-evident audit history | **VERIFIED** | audit integrity 8 |
| Supply-chain scans + SBOM + residual docs | **VERIFIED** (residuals documented) | `security_scans/` |
| Resilience / fail-safe behavior | **VERIFIED** | failure injection 6 |
| Backup / restore procedure | **PARTIAL** | restart-persistence verified; formal pg_dump/restore runbook documented, not yet automated-tested |
| Detection-quality deep-dive (Phase 7) | **PARTIAL** | existing healthcare detector + benign controls pass; dedicated quality corpus deferred |
| HIPAA safeguard gap assessment (Phase 8) | **MISSING** (this release) | deferred to a dedicated assessment doc; no compliance claimed |
| Performance benchmark (Phase 11) | **MISSING** (this release) | deferred; no perf numbers claimed |
| Clean-machine from-scratch (Phase 14) | **PARTIAL** | Docker Compose builds from the repo + downloads deps; not yet run on a separate physical host |
| Dependency clean audit | **BLOCKED** | starlette ≥0.49 needs FastAPI ≥0.120 / pydantic ≥2.9, conflicts pinned core |
| Hosted GitHub Actions CI | **BLOCKED** | repository Actions disabled (`actions/permissions` → `enabled:false`) |

## F. Release verdict

**BLOCKED.**

Rationale (per the stated release-gate rule that unexecutable required checks
force BLOCKED regardless of local results):
1. **Hosted GitHub Actions CI cannot execute** — Actions is disabled at the
   repository level, so no required hosted check can run. Owner action needed:
   enable Actions in repo Settings → Actions, then re-run CI.
2. A fully clean dependency audit is **blocked** by the pinned-core pydantic
   constraint (documented, low residual applicability).
3. Phases 7 (detection-quality corpus), 8 (HIPAA gap assessment), 11
   (performance), and part of 14 (separate-host clean-machine) are not completed
   in this release and are marked PARTIAL/MISSING above — not silently omitted.

**Local/containerized security verification is strong** (280 passing tests, 68
security-specific; hardened stack verified live). The product is a stronger
controlled-pilot *candidate* than at Milestone C, but the milestone's own gate
definition requires it be reported as **BLOCKED** until hosted CI runs and the
remaining PARTIAL/MISSING gates are closed. No production-readiness or HIPAA
claim is made.
