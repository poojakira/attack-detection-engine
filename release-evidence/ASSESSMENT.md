# AEGIS-QA-01 remediation assessment

Frozen clean source: **8ae9090b560871d1e584d717734693bb570fffae**, branch `codex/local-workbench-20261116`, product `poojakira/attack-detection-engine`, application1.1.0/rules clinical-access-1.1. Decision: **PARTIAL master-contract completion; remediation TESTED and OBSERVED, awaiting independent closure.** No remote write or branch deletion was performed.

The independent review of50b8d82 reproduced a medium consistency defect: a delayed mount case-list response could overwrite a newer post-import list. No persisted data was lost. Every case-list refresh now shares a monotonic request sequence. Both success and error callbacks require the latest sequence and a mounted component; unmount invalidates the sequence. Editor changes do not invalidate the initial list. Mount and post-import refreshes use the same helper. Detection, persistence, authentication, RBAC, organization isolation and all backend source remain unchanged.

The actual Chromium regression holds the first authenticated GET /cases response after fetching real API bytes, edits the form, imports the first-party synthetic dataset through the real detector/PostgreSQL, waits for the newer list to display its new case, releases the old response, waits for rendering, then requires that same generated case ID to remain selectable. `browser/browser.json` records `new_case_visible_after_old_list: true`, case `case-1be51bd0bdbd43ed9c7af121463040d2`. No detector/API response is fabricated.

## Fresh checks against this commit


- 327 individual JUnit testcases passed,0 failed/errors/skipped,0 native subtests. Coverage2489/3018 lines,82.47%, preserving the53% gate. PostgreSQL and exact core087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b/v19.2 bundles were present; no platform tests skipped.
- 9 browser checks passed,0 page errors, including the new race plus real import/source/normalized evidence, threshold rerun/delta/export, saved-case reload, obsolete export checksum cancellation, delayed File.text precedence, XSS-shaped metadata, malformed input and mobile layout.
- 7 installed-wheel checks passed with freshly rebuilt/reinstalled wheel: packaged migration startup, canonical detection/correlation/PostgreSQL, exact-dataset rerun, actual API restart, retained case/export, and UNKNOWN source despite an unrelated enclosing Git HEAD.
- Ruff lint/format, Pyright0 errors/warnings, actionlint, shell syntax, pip check, repository security scanner, Python wheel/sdist and React TypeScript/esbuild builds all passed. Inventory covers158 files, with0 syntax errors or missing local Markdown targets;18 configuration files parsed.
- Fresh pip-audit/npm audit report0 known vulnerabilities. The unchanged medium/high Bandit gate passes. Full-severity Bandit exits1 for6 reviewed LOW findings; raw output and review remain visible. Detect-secrets reports51 reviewed public digest/revision or synthetic local fixture/example candidates; no suppression baseline was created.

The parent independently observed the literal launcher and actual restart/persistence on source50b8d82; its evidence remains separately scoped under `launcher-orchestration`. This remediation changes UI/list handling, its browser regression and documentation only. It does not relabel the earlier literal-orchestration proof as an8ae run. Current-source component/browser/wheel startup and restart proof are fresh. Hosted CI and independent closure belong to the parent; actionlint success alone is not a hosted run.

## Evidence and resource disposition

All prior50b8d82 final evidence is preserved intact under `superseded-50b8d82-before-QA01`, clearly separated from current `final`. The independent defect report is preserved under `/workspace/work/reviews/attack-detection-engine`. The current manifest lists exact command intervals/exits, source/build/dependency/input/config hashes and artifact checksums. Source and wheel server processes were terminated. The original test PostgreSQL container remains running; `aegis_independent` is retained. The separate launcher container, retained volume/private ignored state and unrelated processes were untouched. Only disposable npm download cache was reclaimed after npm tasks completed when disk reached11MiB free.

Full master-contract obligations remain PARTIAL: independent closure, remote branch/protection/publication governance, exhaustive historical-document/operational/privacy review, full FHIR conformance, parser/worker sandbox and hard detector deadline, coordinated multi-process quotas, externally anchored audit integrity and production backup/restore. No real PHI, field-efficacy claim, public deployment or production readiness is established. The primary workflow remains offline deterministic investigation with explicit uncertainty.
