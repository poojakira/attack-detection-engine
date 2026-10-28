# Milestone D — Phase 0 Baseline Verification (2026-10-27)

Branch: `feat/milestone-d-hardening` (forked from `feat/milestone-c-platform`).
Reproduced, not assumed.

## Environment
- Python 3.12.3, isolated venv, pinned `attack-v19-core@087accffc7` (19.2.0).
- PostgreSQL 15 (Docker `aegis-pg` @127.0.0.1:55432), Docker 29.3.0, Node 20.
- `AEGIS_DATABASE_URL=postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis`.

## Reproduced results
- `ruff check detection_engine tests scripts .github/scripts` → All checks passed.
- Full suite (`pytest -q`) → **212 passed** (incl. real-PostgreSQL integration +
  8 end-to-end API/security tests).
- Open PRs confirmed: #47 (healthsec→main), #48 (milestone-c→healthsec), plus
  Dependabot PRs #41,#43–#46.

## Confirmed weaknesses to remediate (see THREAT_MODEL.md)
- Stateless JWT: role/org/disabled-state not re-checked against DB (S2/E2).
- bcrypt 72-byte silent truncation → auth ambiguity (Phase 2.4).
- No login throttling (S3). No iss/aud. 
- Docker Compose default DB password + backend on 0.0.0.0:8000 (P1/P2).
- No tamper-evident audit chain (T1/R1).
