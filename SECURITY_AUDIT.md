# Security Audit — attack-detection-engine

**Audit date:** 2026-09-29  
**Scope:** NDJSON CLI boundary, file I/O, detection pipeline, dependency/static-analysis gate, container, and workflows.

## Executive summary

This is a bounded local telemetry CLI rather than a user-facing web or database application.

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| ADE-001 | Info | NDJSON records are capped at 1 MiB and must parse to JSON objects before detection. | Verified |
| ADE-002 | Info | Strings such as subprocess commands are detection content/patterns rather than executed shell commands. | Verified |
| ADE-003 | Info | User auth, UUID tenancy, SQL/XSS, password reset, payments, and web origin controls are not applicable. | N/A |

## Existing controls verified

- Record-size cap and JSON shape validation.
- Security gate evaluates Bandit and pip-audit reports.
- Dependency vulnerability allowlist is explicit.
- Non-root container.
- Secret-hygiene CI.

## Verification plan

Run CI/security/container workflows and re-check file-size/input validation and dependency reports.
