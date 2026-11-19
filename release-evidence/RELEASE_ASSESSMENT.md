# Release assessment: attack-detection-engine

SOURCE: `aa45efd2f9f7e229a0ae7b7f8d77adac18d96e83`  
BRANCH: `codex/local-workbench-20261116`  
ASSEMBLED UTC: 2026-11-19T00:50:47.983222+00:00  
DECISION: **PARTIAL**. No software release, main merge or public full-app deployment is approved by this assessment.

Analysts import bounded synthetic FHIR AuditEvent data through React and authenticated FastAPI, inspect canonical detector/correlation evidence stored in PostgreSQL, change a case threshold, rerun the same dataset and export a checksummed report. This is batch investigation.

## Working entry points

- [Current source README and exact local prerequisites/launch](https://github.com/poojakira/attack-detection-engine/blob/aa45efd2f9f7e229a0ae7b7f8d77adac18d96e83/README.md)
- [Free CPU guided notebook](https://colab.research.google.com/github/poojakira/attack-detection-engine/blob/codex/local-workbench-20261116/notebooks/try_product.ipynb) — public page HTTP 200; actual committed cells passed locally from a fresh public checkout, **hosted Colab kernel NOT VERIFIED**.
- [Readable overview](https://github.com/poojakira/attack-detection-engine/blob/aa45efd2f9f7e229a0ae7b7f8d77adac18d96e83/docs/architecture/overview.svg), [detailed source-mapped architecture](https://github.com/poojakira/attack-detection-engine/blob/aa45efd2f9f7e229a0ae7b7f8d77adac18d96e83/docs/ARCHITECTURE.md), and locally served zoom/pan viewer in `docs/index.html`.

Stateless preview invokes the actual FHIR connector, PatientAccessDetector and CorrelationEngine on 30 synthetic events: threshold 25 produces one finding/incident; threshold 40 produces none. The preview has no database/auth/saved cases. The full local UI uses real PostgreSQL.

The full browser UI remains a local application with its own documented supported inputs. Notebook fixtures do not establish representative field detection, a public hosted full UI, continuous monitoring or multi-user isolation. GitHub Pages configuration failed with HTTP403 "Resource not accessible by integration"; no working Pages URL is asserted. No Render/HF compute resource, paid service, billable provider API call or new credential was used. Existing optional cloud/deployment templates can cost money if separately enabled; see `cost-and-access-audit.json`.

## Fresh execution evidence

The clean candidate has **332 passed, 0 skipped, 0 failed and 0 errors** across 332 individual testcases. Local statement/line coverage is **82.47183565%** (2489/3018); recorded gate 53. Native subtests: {'passed': 0, 'failed': 0, 'skipped': 0}. Separate Python3.10 focused execution: None. Focused/optional/native/browser observations are not added to the individual full-suite total.

See `manifest.json`, `primary-run-manifest.json` where present, `tests-run.json` for Aegis, `executed-test-inventory.json`, original logs, and `browser/` for exact commands, execution times, clean source, environments, skip reasons and actual screenshots/exports. Required named local gates passed. Six LOW full-severity Bandit findings retain exit1 while the unchanged medium/high security gate passes. No check threshold was reduced. Installed-wheel execution uses an unrelated Git project and verifies UNKNOWN instead of inheriting its HEAD.

Current hosted runs: 1 observed; all successful: False. `remote-ci/status.json` records actual URLs and statuses. The current workflow is queued/NOT VERIFIED and has no passing hosted artifact. No publishing workflow or release was invoked.

Two full initial test attempts failed in the verification helper: isolated Python could not see mounted dependencies, then Git was absent for the new provenance test. Their actual 331-pass/1-fail outputs remain preserved. The final helper mounts actual Git and required libraries read-only, with real repository metadata, and exposes the mounted dependency directory through a verification-only .pth. It retains network denial, read-only source, resource limits, default HOME and every test/security assertion. The complete final run passes 332 tests; no fake Git shim or skip was used. Six LOW Bandit findings retain full-severity exit 1; the medium/high gate passes with zero findings. Source/wheel servers and the disposable test database instance were stopped; four synthetic custom dumps remain private and archive listings were validated. No full restore or production backup approval is inferred.

## File, documentation, branch and security audit

178 tracked files were inventoried with SHA256 and per-type validation; all current local documentation target checks, 5 SVG XML parses, notebook JSON/compiled cells and viewer JavaScript syntax passed. Actual viewer controls and every diagram loaded in desktop/mobile Chromium with no page errors. Four sequential product documentation reviewers inspected architecture symbols/enforcement/limits; the parent corrected remaining source mismatches and readability. Historical documents/artifacts retain their dated source bounds. This audit does not certify every external link's factual content, chronology, optional toolchain or cloud/deployment command.

Only `main` and `codex/local-workbench-20261116` remain as remote branches at recorded readback. Main remains `b631f31df52e9a7477cbc65dff9b4f46758f71a7`. 12 additional tips were preserved in verified annotated recovery tags and a private verified bundle before exact-lease atomic deletion. 10 associated PRs are closed without merging their unreviewed changes. Unique security/cross-language work remains recoverable, not advertised as current functionality. Restore commands, tag/SHA pairs and final PR states are in `branch-disposition.json`. Tags are not extra branches. Future dependency automation may create branches; its protections were not disabled.

The reviewed offline Gitleaks scan covered all local Git refs/history, including recovery history, with redaction and default detectors. It produced 149 historical generic-rule occurrences, explicitly classified in `secret-history-triage.json`; no confirmed provider credential was found in that reviewed scope. Current tracked-file scanning found no new heuristic secret values. Hashes, public signing fingerprints and intentional synthetic/local test examples are distinguished from provider credentials. No live credential validation, suppression baseline or absolute secret-absence claim is made. Private raw history/author context, backups, product credentials, session tokens and real patient/user data are excluded from publication.

## Independent review boundary and remaining release gates

Historical focused independent security reviews remain attached to their real earlier source. Current whole-suite/browser/build/type/security checks were freshly executed by the parent. Documentation role separation is not a newly completed independent adversarial closing review at this candidate. HF's explicit blocked review remains blocked, with no bypass or reroute. No perfect/production-ready claim is justified.

- Current hosted CI is queued/NOT VERIFIED; no hosted passing result or product-container runtime is asserted.
- The API does not provide hard process isolation/deadlines for parser/detector computation; the 15-second body deadline bounds receipt only.
- Multiprocess quotas, full FHIR conformance, external audit anchoring and automotive browser integration remain missing or NOT VERIFIED.
- Real PHI handling, production privacy/recovery/load approval and hostile public hosting remain NOT VERIFIED; use synthetic inputs only.

`product-matrix.json` maps current implementation/evidence and gaps. `executed-test-inventory.json` identifies actual positive/negative/recovery cases and skipped checks. A new current-source independent review, the missing product-specific acceptance gates and deployment-specific signoff would be required to change this decision.

NEXT SAFE ACTION: review the existing draft PR and the source-scoped archive; complete the listed acceptance gates. Any later source change requires fresh applicable regression/browser/security evidence.
