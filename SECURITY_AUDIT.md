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
The targeted post-merge Windows Python 3.12 run passed 29 tests; that
number must not be presented as a full-repository test total.
