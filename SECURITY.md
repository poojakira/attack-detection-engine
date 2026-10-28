# Security Policy

## Reporting a Vulnerability

Please do not open a public issue for a suspected security vulnerability.

If GitHub private vulnerability reporting is enabled for this repository, use the repository's **Security** tab to submit a private report. Otherwise, contact the maintainer directly through the contact information on the GitHub profile.

Include:
- a clear description of the issue
- affected files or components
- reproduction steps or a minimal proof of concept
- expected impact
- any suggested remediation

## Response Targets

- **48 hours:** acknowledge receipt
- **5 days:** initial assessment and severity classification
- **30 days:** fix, mitigation, or remediation plan when practical

Please avoid accessing, modifying, or exfiltrating data that is not necessary to demonstrate the issue.

<!-- credential-response:start -->
## Credential and secret handling

- Real API keys, tokens, passwords, private keys, cloud credentials, and populated environment files must never be committed.
- Local users must create their own `.env` from the repository's safe template when environment variables are needed, and must supply **their own** credentials. CI/CD credentials belong in GitHub repository/environment secrets or an external secret manager, not in source or workflow YAML.
- If a real credential is exposed, treat it as compromised even if the commit is quickly deleted. **Revoke or rotate the credential at its provider first.** Then remove it from the current tree, reachable Git history, logs/artifacts, examples, screenshots, and documentation as applicable.
- Rewriting Git history or deleting a file does **not** revoke a credential. Provider-side rotation/revocation is required.
- Placeholder/test credentials must be clearly marked and must not be valid for real services.
<!-- credential-response:end -->


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

## Milestone D investigation-platform hardening (2026-10-27)

The Aegis investigation platform (`detection_engine/platform/`) adds, with
regression tests (see `MILESTONE_D_SECURITY_REPORT.md` and `THREAT_MODEL.md`):

- Argon2id password hashing (OWASP) with versioned formats and verify-then-
  upgrade migration from legacy bcrypt; the prior 72-byte truncation ambiguity
  is fixed.
- JWT with explicit algorithm allowlist, issuer/audience and required-claim
  validation; DB-backed principal resolution so disabled accounts and role/org
  changes fail closed, plus `token_version` revocation.
- Login throttling with generic errors (no user enumeration).
- Per-organization tamper-evident audit hash chain over investigation actions
  (tamper-EVIDENT, not tamper-proof — see trust limitations in the report).
- Hardened Docker Compose: no default DB password (fails closed), PostgreSQL not
  published to the host, localhost-bound dev ports, non-root / read-only /
  cap-dropped / no-new-privileges containers, sanitized `.env.example`, and a
  startup secure-config gate.
- Web hardening: security headers, body-size limit independent of
  Content-Length, restricted CORS, generic 500 responses, readiness that does
  not leak secrets.
- Supply chain: python-jose/ecdsa replaced with PyJWT; FastAPI/starlette
  upgraded; SBOM + bandit + pip-audit recorded under `security_scans/`.

Release verdict for Milestone D: **BLOCKED** — hosted GitHub Actions is disabled
at the repository level so required CI cannot execute; a fully clean dependency
audit is also pin-constrained. Local/containerized verification (280 tests) is
reported separately and is not a production or HIPAA claim.
