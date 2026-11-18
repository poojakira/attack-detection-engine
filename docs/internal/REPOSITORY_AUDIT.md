> **Historical/source-bounded record.** Metrics, branch/settings statements, dependency constraints, commands and author-recorded external observations below describe their cited earlier snapshot. They are not current documentation-head execution or production/privacy approval. Current state and review limits: [evidence status](../EVIDENCE.md). External chronology, dataset/legal/field assertions were not independently revalidated in this documentation pass. Do not execute destructive, credential-bearing, clinical-data or deployment examples merely to reproduce a historical record.

# Read-only forensic baseline: poojakira/attack-detection-engine

UTC: 2026-11-17T02:26:33.787101+00:00. Audit role: independent forensic reviewer. Decision: PARTIAL baseline; product release NOT VERIFIED.

## Repository identity

Authoritative connected-account match: `poojakira/attack-detection-engine`; public; remote `https://github.com/poojakira/attack-detection-engine.git`; default `main`; HEAD `b631f31df52e9a7477cbc65dff9b4f46758f71a7`. Full fetched reachable history contains 174 commits; no shallow clone, no source/remote mutation performed. No AGENTS.md found. Commit metadata and all reachable commit parents/dates/subjects: `git-baseline.json`, `history.txt`.

Initial checkout status: ''. MCP six trailing mixed-CRLF lines normalize on checkout under .gitattributes; preserved in normalization.patch. Do not attribute these to user edits. No reset or overwrite performed.

## Product baseline

Capabilities: Main already contains actual FHIR AuditEvent connector, normalized models, real deterministic clinical detectors/correlation, PostgreSQL SQLAlchemy persistence/migrations, authenticated FastAPI/RBAC/org isolation, React investigation frontend and exports. Also offline CAN/firmware/ARM workflows.

Gaps: React UI has login/overview/queue/investigation but no browser FHIR import or supported rule-edit/rerun workflow. README says platform/FHIR only on branches, contradicting source already in main via squash integration. Export/rerun source provenance needs reconciliation.

Risk: HIGH verification gap: Postgres-dependent tests skip when database absent. Main CI only workflow_dispatch; exact-head action runs retrieved are dependency graph updates, no product CI. Pin stack is old; review dependency vulnerabilities before release. Test pg_engine drops all schema tables: only run with isolated disposable database.

Minimal complete journey: Launch isolated local Postgres plus API/React -> authenticated synthetic FHIR import -> actual normalization/detect/correlate/persist -> evidence/timeline -> bounded condition change and same dataset rerun -> provenance report.

Enforcement/source entrypoints: detection_engine/platform/api.py: create_app, ingest_fhir_auditevent; connectors/fhir_auditevent.py: FhirAuditEventConnector.parse; ingestion.py: IngestionService; correlation.py: CorrelationEngine; repository.py; auth.py: resolve_principal, LoginThrottle; bootstrap.py: build_app; dashboard-ui/src/api/client.ts real fetch API.

Recommended next milestone: Use main, do not merge old milestone branches blindly: semantic/squash comparison needed. Extend React with FHIR import and supported isolated case rerun. Start disposable real Postgres with Docker and exact attack-v19-core pin; never execute destructive pg fixtures against user DB. Reenable product CI triggers without weakening gates.

## Current CI and executable evidence

No CI workflow run found for exact main b631f31d among 7 returned head runs (all dependency-graph updates). CI source triggers only workflow_dispatch; prior README Actions-disabled claim not independently re-established. These graph update successes are not test evidence.

Fresh local command (from repository root):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=. /workspace/work/tooling/venv/bin/python -m pytest -p no:cacheprovider tests/test_healthcare_schema.py tests/test_platform_models.py -q --junitxml=/workspace/work/audit/attack-detection-engine/baseline-junit.xml
```

Result: BLOCKED: 2 collection errors (ModuleNotFoundError: pydantic) in generic audit venv; no tests executed; no coverage. Full database/runtime dependencies not installed during read-only baseline. Actual captured output: baseline-tests.log; JUnit: baseline-junit.xml. Tests were run from original main source in audit tooling venv; this is not a candidate release run. Python 3.12.14; Node 24.22.1; Linux. Generic tooling venv is not the complete pinned product dependency environment. Exact run timestamps/counts are in JUnit. Final candidate tests, full regression, browser E2E, supply-chain audit, container build and release validation are NOT VERIFIED. Do not treat retrieved historic CI as fresh evidence.

## File inventory and validation

Every tracked default-branch path inventoried: **143**. `inventory.json` records path, size, SHA256, type, symlink state, AST/JSON syntax validation; `tracked-files.txt` is complete path list. Python AST syntax and tracked JSON parsing completed with 0 errors. `configuration-validation.json` records safe TOML and shell syntax checks. `documentation-inventory.json` inventories 25 text documentation files and candidate broken local links; external URLs, anchors, all facts/examples and media visual accessibility remain NOT VERIFIED. `workflow-audit.json` records source workflow pin/permissions indicators; parser/trigger and gate semantics need final review. No arbitrary tracked binary/executable or model was executed. Binary fixture hashes are inventory evidence, not proof of safety. No submodules. Test classes inferred from source include unit, integration, negative/adversarial; exact taxonomy and coverage exclusions must be reviewed for candidate.

All tracked-file semantic/security review is NOT COMPLETE. All remote branch tips have diff-stat and changed-path evidence; only selected important source paths were reviewed semantically. This records the audit boundary rather than falsely claiming every historical branch file/claim was verified.

## Branch governance

All refs preserved. Ahead/behind are ancestry counts, not evidence that squash-merged content is missing. No branches merged/deleted; none is yet DELETE ELIGIBLE. Full unique commit lists are in git-baseline.json. PR metadata latest first-page stored in github-prs.json (max 100; older pagination not yet exhausted). Open PRs visible in first page retained. Tags: none. Releases: none returned. Rulesets: empty returned. Branch-protection inspection BLOCKED by GitHub integration 403; lack of visibility does not establish absent protection. Workflow collection endpoint was rejected; checked-in workflow sources and action-run endpoints were read.

| Ref | SHA | Ahead / behind main | Disposition | Related PR |
|---|---|---:|---|---|
| `refs/heads/main` | `b631f31df52e9a7477cbc65dff9b4f46758f71a7` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/HEAD` | `b631f31df52e9a7477cbc65dff9b4f46758f71a7` | 0 / 0 | KEEP |  |
| `refs/remotes/origin/dependabot/github_actions/actions/setup-python-7.1.0` | `f0858f00ab7ce0cd2b5d655b372f245ad4030e83` | 1 / 1 | HOLD FOR REVIEW | #46 open |
| `refs/remotes/origin/dependabot/github_actions/actions/upload-artifact-7.0.2` | `e40e39d7e45581ca4153606955cb4dfc4530b278` | 1 / 1 | HOLD FOR REVIEW | #43 open |
| `refs/remotes/origin/dependabot/github_actions/docker/login-action-4.8.0` | `2c7784f50af50ff11bd0d61d1c7deb0a3ef7d2a1` | 1 / 0 | HOLD FOR REVIEW | #57 open |
| `refs/remotes/origin/dependabot/github_actions/docker/setup-buildx-action-4.4.1` | `2c8957e50223b6b3603e0d833867fe81d8afe232` | 1 / 1 | HOLD FOR REVIEW | #44 open |
| `refs/remotes/origin/dependabot/npm_and_yarn/dashboard-ui/vite-8.3.5` | `ee296a2f3a6b7e521d3383a692a7ba8da5214daf` | 1 / 0 | HOLD FOR REVIEW | #52 open |
| `refs/remotes/origin/dependabot/pip/bandit-gte-1.9.4` | `789d781c980f0b0027d4e157a88427684de3fe5b` | 1 / 0 | HOLD FOR REVIEW | #56 open |
| `refs/remotes/origin/dependabot/pip/build-gte-1.6.1` | `04ece9c100bf12e24650a935ceb430da603089bd` | 1 / 0 | HOLD FOR REVIEW | #53 open |
| `refs/remotes/origin/dependabot/pip/pydantic-2.14.2` | `cc70338d181e466138377c315f3fe69f6950dc96` | 1 / 0 | HOLD FOR REVIEW | #54 open |
| `refs/remotes/origin/dependabot/pip/starlette-1.3.1` | `dfd242a305c4d8a30f4c8fd0b73a184607e8dadf` | 1 / 0 | HOLD FOR REVIEW | #51 open |
| `refs/remotes/origin/dependabot/pip/starlette-1.7.0` | `168af818ac5ab3a0acbadba32a9001b843789df6` | 1 / 0 | HOLD FOR REVIEW | #55 open |
| `refs/remotes/origin/feat/automotive-firmware-can` | `1b647ea9b2df10708379ca2c05172ef77fb3253f` | 2 / 5 | HOLD FOR REVIEW | #38 closed merged |
| `refs/remotes/origin/feat/healthsec-detection` | `44c2ca2c6f0f07c590107091acd381ddb36d7ea0` | 28 / 1 | HOLD FOR REVIEW | #47 closed merged |
| `refs/remotes/origin/feat/milestone-c-platform` | `75b15dba12016cd3d68073d17b70dcb2ba3afebb` | 26 / 2 | HOLD FOR REVIEW | #48 closed merged |
| `refs/remotes/origin/feat/milestone-d-hardening` | `b4f5e137b572030f62a0190f295f59f63e491ad9` | 25 / 2 | HOLD FOR REVIEW | #49 closed merged |
| `refs/remotes/origin/feat/milestone-e-connectors` | `c24dc59b84a981e7c57f53357e14ce85ea5f80fc` | 26 / 2 | HOLD FOR REVIEW | #50 closed merged |
| `refs/remotes/origin/feature/cross-language-hipaa-admin-detection` | `660e1c6c47e862a8c2818bed98f5f57aa23c4210` | 1 / 1 | HOLD FOR REVIEW |  |
| `refs/remotes/origin/fix/automotive-validation-docs` | `988417f79dba6262410d5d3a783922076137c096` | 1 / 4 | HOLD FOR REVIEW | #39 closed merged |
| `refs/remotes/origin/fix/full-test-index-fixture` | `72f1fe9cff6d6c7c5b859763624ea3df09863252` | 1 / 3 | HOLD FOR REVIEW | #40 closed merged |
| `refs/remotes/origin/main` | `b631f31df52e9a7477cbc65dff9b4f46758f71a7` | 0 / 0 | KEEP |  |

## Phase report

PRODUCT: poojakira/attack-detection-engine
SOURCE: b631f31df52e9a7477cbc65dff9b4f46758f71a7 BRANCH: main UTC: 2026-11-17T02:26:33.787101+00:00
PHASE: 0 forensic baseline
DONE: complete default tracked-path/hash inventory; reachable refs/history; selected engine/UI/docs/workflow analysis; raw provider evidence.
EXECUTED: command above; safe Python AST/JSON/TOML/bash syntax checks; git read-only inventory; GitHub GET metadata.
RESULTS: BLOCKED: 2 collection errors (ModuleNotFoundError: pydantic) in generic audit venv; no tests executed; no coverage. Full database/runtime dependencies not installed during read-only baseline.
NEGATIVE / ADVERSARIAL TESTS: focused existing tests named by command; no new full acceptance attack matrix executed.
CLAIMS VERIFIED: source existence and selected behavior only; see checks above.
CLAIMS RETRACTED: no source changes during audit; unsupported/stale claims flagged above for implementation/docs reviewer.
BRANCH CHANGES: none; all KEEP or HOLD FOR REVIEW.
RISKS / BLOCKERS: incomplete release acceptance and provider protection visibility; product-specific items above.
DECISION: PARTIAL baseline; NOT VERIFIED release.
NEXT SAFE ACTION: Use main, do not merge old milestone branches blindly: semantic/squash comparison needed. Extend React with FHIR import and supported isolated case rerun. Start disposable real Postgres with Docker and exact attack-v19-core pin; never execute destructive pg fixtures against user DB. Reenable product CI triggers without weakening gates.
