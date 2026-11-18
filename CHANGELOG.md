# Changelog

## 1.1.0 candidate remediation — 2026-11-18

- Fixed AEGIS-QA-01: every saved-case refresh now shares a monotonic request sequence, so a delayed initial response cannot overwrite a newer post-import list. Both success and error callbacks discard obsolete/unmounted completions; editor changes do not discard the initial list.
- Added an actual-browser regression that holds real API list response bytes across an actual synthetic import, then releases the older response and verifies that the new persisted case remains selectable.

## 1.1.0 — Local workbench candidate, 2026-11-17

- Added authenticated React FHIR import, real PostgreSQL case/run evidence, source/normalized timeline, case-level threshold rerun, finding delta and checksummed JSON export.
- Preserved the canonical clinical detector/correlator, existing incident actions, Argon2id/revocation/RBAC and organization isolation.
- Corrected invented FHIR read/success/timezone observations and silently dropped unsupported input; missing optional action/outcome remains UNKNOWN.
- Bounded actual HTTP body receive bytes and time before parsing; added local host, input/config/rate/concurrency bounds and immutable rerun transactions.
- Added source/version/config/input provenance, honest uncertainty, local launcher, regression/browser checks and source-scoped evidence contract.
- Updated the framework/router dependencies compatibly and replaced the vulnerable Vite build chain with static esbuild plus TypeScript checking.
- Added migration `b2c3d4e5f6a7`; rollback discards case/run tables only after an owner-approved backup. The master contract remains PARTIAL pending independent review, branch/publication governance and operational/documentary gaps described in the guide.

Earlier milestone documents retain their original historical dates and scope. No new authorship dates or field-performance claims are inferred from commit history.
