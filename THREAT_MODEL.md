# Aegis HealthSec — Threat Model (Milestone D)

Methodology: STRIDE over the investigation platform's attack surfaces. Each
threat lists entry point, assets, preconditions, impact, current mitigation,
residual risk, severity, remediation, and the verification test that proves the
control. "Mitigated" is only claimed where a test exercises the control.

Scope: controlled-pilot readiness in an isolated environment with synthetic
telemetry and de-identified MIMIC-IV Demo clinical context. Not live ePHI.

## Attack surfaces

FastAPI endpoints · JWT auth · password handling · admin bootstrap · RBAC ·
organization isolation · PostgreSQL · event ingestion · detector execution ·
correlation · incident evidence · React dashboard · Docker/networking · env
vars/secrets · dependencies/build artifacts · clinical context · audit log ·
backup/recovery.

## Threats (STRIDE)

### S — Spoofing

| ID | Threat | Entry | Impact | Current mitigation | Residual | Severity | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| S1 | Forged/tampered JWT | Authorization header | Impersonation | HS256 signature verified, explicit alg allowlist | Secret strength depends on deploy | High | Require strong `AEGIS_JWT_SECRET`; reject weak/short in prod startup | `test_tampered_token_rejected`, startup secret check |
| S2 | Token replay after logout/disable | header | Access as disabled user | **(D)** DB-backed principal resolution + `token_version` | Access window ≤ token TTL unless version bumped | High | revoke via `token_version` + `is_active` check on every request | `test_disabled_account_token_rejected`, `test_role_change_invalidates_token` |
| S3 | Login brute force / credential stuffing | `/auth/token` | Account takeover | **(D)** per-user+IP throttling + lockout | In-memory limiter resets on restart (documented) | Medium | rate limit + generic errors | `test_login_lockout`, `test_no_user_enumeration` |

### T — Tampering

| ID | Threat | Entry | Impact | Current mitigation | Residual | Severity | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| T1 | Audit record alteration | DB / direct SQL | Repudiation of analyst actions | **(D)** append-only hash-chain over `investigation_actions` | DB admin with write access can rewrite chain + anchors (documented, not tamper-proof) | Medium | hash chain + documented trust boundary | `test_audit_chain_detects_tamper` |
| T2 | Cross-tenant incident/finding association | repository writes | Data integrity across orgs | org-scoped writes; FK within org | Needs adversarial coverage | High | adversarial cross-org tests + scoping asserts | `test_cross_org_*` suite |
| T3 | SQL injection | API params | DB compromise | SQLAlchemy parameterized queries (no string SQL) | — | Low | keep ORM, no raw SQL from input | `test_injection_strings_safe` |

### R — Repudiation

| ID | Threat | Entry | Impact | Current mitigation | Residual | Severity | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| R1 | Analyst denies an action | investigation API | Dispute | every write → `InvestigationAction` (who/when/prev/new/org) | trust depends on T1 chain | Medium | audit record + hash chain | `test_audit_history_complete`, e2e history assertions |

### I — Information disclosure

| ID | Threat | Entry | Impact | Current mitigation | Residual | Severity | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| I1 | Cross-org data leakage | all incident endpoints | ePHI-adjacent exposure | org from token only; cross-org → 404 | Needs per-endpoint adversarial proof | High | adversarial tests on every path | `test_cross_org_*` |
| I2 | Secret/connection string in errors | `/readiness`, 500s | Secret leak | **(D)** generic 500, readiness returns status only | — | Medium | exception handler + readiness sanitization | `test_readiness_no_secret_leak`, `test_internal_error_generic` |
| I3 | Clinical content in logs/evidence/exports | ingestion, evidence, export | PHI leak | pseudonymous refs, `redacted_evidence`, extra-forbid schema | — | High | schema PII guard + evidence projection | healthcare schema tests + `test_evidence_no_record_content` |
| I4 | Token/password logging | app logs | Credential leak | no secret logging (reviewed) | — | High | code review + grep gate | second-review grep |

### D — Denial of service

| ID | Threat | Entry | Impact | Current mitigation | Residual | Severity | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| D1 | Oversized / deeply nested payload | `/events` | Memory/CPU exhaustion | **(D)** body-size limit (not Content-Length trusting), batch cap | Per-record depth bounded by schema | Medium | size middleware + batch cap | `test_oversized_body_rejected`, `test_batch_limit` |
| D2 | Unbounded incident queries | list endpoints | Slow queries | `limit` capped (≤200), pagination | — | Low | enforced cap | `test_list_limit_capped` |
| D3 | DB outage reported as success | ingestion | Silent data loss | commit-or-error; readiness 503 | — | High | no false-healthy | `test_db_outage_not_false_success` |

### E — Elevation of privilege

| ID | Threat | Entry | Impact | Current mitigation | Residual | Severity | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| E1 | Auditor performs writes | write endpoints | Unauthorized change | `_require_write` role gate | Needs per-endpoint proof | High | role gate + tests | `test_auditor_cannot_modify` + per-endpoint |
| E2 | Role/org escalation via stale token | header | Elevated access | **(D)** DB-backed role/org resolution | window ≤ TTL unless version bump | High | DB principal + token_version | `test_role_change_invalidates_token` |
| E3 | Insecure admin bootstrap | env seed | Backdoor admin | env-driven, no hardcoded admin; **(D)** refuses weak/empty secret | operator must set strong creds | Medium | startup validation + docs | `test_bootstrap_requires_strong_secret` |
| E4 | Container privilege escalation | Docker | Host compromise | **(D)** non-root, no-new-privileges, dropped caps | shared kernel | Medium | compose security_opt + user | compose config review + run |

### Deployment / supply chain

| ID | Threat | Entry | Impact | Current mitigation | Residual | Severity | Remediation | Verification |
|---|---|---|---|---|---|---|---|---|
| P1 | Default DB password | compose | Unauthorized DB access | **(D)** no default; `AEGIS_DB_PASSWORD` required | operator responsibility | High | remove default + fail closed | compose rejects unset secret |
| P2 | Backend exposed on all interfaces | compose ports | Remote attack | **(D)** dev ports bound to 127.0.0.1; TLS proxy documented | — | Medium | localhost bind + TLS docs | compose config review |
| P3 | Vulnerable/typosquatted deps | build | RCE/backdoor | pinned core commit; pip-audit/npm audit/bandit; SBOM | residuals documented | Medium | scans + pinning | Phase 9 artifacts |

## Priority remediation order (this milestone)

1. **High**: S2/E2 (stateless token → DB-backed + revocation), P1 (default DB
   password), I1/T2 (adversarial cross-org), D3 (DB-outage false success).
2. **Medium**: S3 (login throttling), I2 (error/readiness leak), D1 (body
   limits), T1/R1 (audit hash chain), E4/P2 (container hardening).
3. Supply-chain scans + residual documentation.

Items marked **(D)** are implemented/strengthened in Milestone D and each has a
regression test listed in the Verification column.
