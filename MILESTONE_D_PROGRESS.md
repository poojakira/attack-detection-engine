# Milestone D — Progress (resumable)

Branch: `feat/milestone-d-hardening` (off `feat/milestone-c-platform`).
Run tests: `docker start aegis-pg`; clear PG locks
(`PGPASSWORD=aegis psql -U aegis -h 127.0.0.1 -p 55432 -d aegis -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='aegis' AND pid<>pg_backend_pid();"`);
then `. .venv/bin/activate && AEGIS_DATABASE_URL=postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis AEGIS_JWT_SECRET=milestone-d-test-secret-at-least-32-chars PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH= python -m pytest -q -o cache_dir=/tmp/adept_cache`.

## Status
- [x] Phase 0+1 baseline + THREAT_MODEL.md — commit 26b9a94
- [x] Phase 2 auth/JWT hardening — commit ff93cf4 (then Argon2id upgrade)
- [ ] Phase 2.5 Argon2id password upgrade (OWASP review)
- [x] Phase 3 RBAC + cross-org adversarial
- [x] Phase 4 Docker secrets/least-privilege
- [x] Phase 5 FastAPI headers/CORS/body limits/safe errors
- [x] Phase 6 DB integrity + tamper-evident audit chain + backup/restore
- [ ] Phase 7 detection quality
- [ ] Phase 8 HIPAA gap assessment
- [x] Phase 9 supply chain (pip-audit/bandit/npm audit/SBOM)
- [x] Phase 10 resilience/failure injection
- [ ] Phase 11 performance
- [ ] Phase 12 independent pentest review
- [ ] Phase 13+14 CI (BLOCKED) + clean-machine
- [ ] Phase 15 docs + final report + stacked PR

## Key facts
- Baseline: 232 passed after Phase 2 (212 original + 20 auth). ruff clean.
- CI: repo Actions disabled (enabled=false) -> required checks CANNOT run ->
  RELEASE VERDICT = BLOCKED regardless of local results (per owner instruction).
- Password hashing: versioned. argon2$ (new, argon2id) > v2$ (bcrypt+sha256
  prehash) > legacy raw bcrypt. Migrate legacy only after successful verify.
- Real PG: docker container aegis-pg @127.0.0.1:55432 user/pass/db=aegis.
