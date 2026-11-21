# Security policy

## Scope and support

Candidate software/API is 1.1.0; rules are `clinical-access-1.1`. Main is the integration branch. No backport, staffed on-call, acknowledgment deadline or fix-time commitment is established. Release status is **PARTIAL**, with exact-source results in [the evidence guide](docs/EVIDENCE.md); version strings or green workflow names do not approve production use.

The local workbench performs authenticated deterministic investigations against a dedicated PostgreSQL database. It is not a real-time EDR, authorization engine, full FHIR validator, anonymizer or HIPAA certification. Use only synthetic data for this evaluation. Original input JSON is retained and exports may include fields omitted from normalized metadata.

## Vulnerability reporting

Use GitHub private vulnerability reporting if enabled, or contact the maintainer through the repository owner's profile. Do not publish credentials or exploitable details in a public issue. Include affected commit/version, prerequisites, a minimal synthetic reproduction, expected/actual behavior and impact. A report does not establish a response SLA. Avoid accessing unrelated data or systems.

## Credentials and private data

- Never commit actual keys, passwords, bearer/session tokens, private keys, populated environment files, clinical inputs or private recovery backups.
- The local workflow requires no provider credentials. Keep the generated development database password file paired with its retained volume and private.
- Revoke/rotate exposed credentials at their provider/deployment first, preserve evidence, then remediate source/history/log/artifact exposure. Deleting a file or rewriting Git history does not revoke a credential.
- Prefer operator-managed short-lived identity and a suitable secret store for independently authorized deployments. Protect account/policy/clinical context in process memory, logs and exports.
- Synthetic test credentials are fixtures, not production defaults. Do not live-validate a heuristic secret-scan match against external services.

## Implemented boundaries and residual risk

New passwords use Argon2id; supported legacy bcrypt formats verify and migrate only after successful login. JWT validation uses PyJWT with an algorithm allowlist, issuer/audience/required claims and authoritative database user/token-version checks. Roles and organization-scoped queries control server data access. These controls depend on the trusted host, signing secret, database and correct integration; they do not provide SSO or a public multi-tenant approval.

Actual received HTTP bytes/time are bounded before parsing. Input/configuration limits, rate/concurrency controls, transactions, safe error responses, restrictive headers and escaped React output cover tested cases. The parser/detector still runs in the API process without a separate hard CPU/memory execution sandbox. Quotas/rate limits do not fully coordinate across processes. Audit chains/checksums are not externally anchored and a database/host owner can rewrite state. Reference/identifier heuristics cannot guarantee de-identification. [Threat model](THREAT_MODEL.md) and [workbench limits](docs/WORKBENCH.md#threat-model-and-operations) map these controls and gaps.

Optional CAN/source/ELF, ATT&CK pipeline, MIMIC adapter and Compose paths have their own data/toolchain/deployment prerequisites. No live vehicle, real patient, representative field-efficacy, external penetration-test or regulatory certification claim is established by their existence. Dated security scans record their cited snapshots; later audits must run at the new candidate without suppressing findings.
