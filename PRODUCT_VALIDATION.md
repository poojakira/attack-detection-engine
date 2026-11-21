# Product validation and acceptance scope

## Supported user job

An authenticated analyst imports bounded synthetic FHIR AuditEvent JSON, inspects actual persisted clinical findings/correlation with source/normalized evidence, changes a case threshold, reruns the retained dataset, compares immutable runs and downloads a checksummed JSON report. The first-party 30-event bulk-read fixture at thresholds 25 and 40 defines a reproducible acceptance example, not field efficacy.

The implementation uses actual React/FastAPI/PostgreSQL and canonical detector/correlator code. [WORKBENCH.md](docs/WORKBENCH.md) maps the architecture/API, uncertainty, errors, lifecycle and testing. [PLATFORM.md](PLATFORM.md), [HEALTHCARE_SECURITY.md](HEALTHCARE_SECURITY.md) and [AUTOMOTIVE_SECURITY.md](AUTOMOTIVE_SECURITY.md) describe distinct supported paths; those paths are not automatically browser features.

## Acceptance matrix

| Property | Implemented/tested relationship | Remaining boundary |
|---|---|---|
| Import → detector → correlation → persistence | Workbench/API/connector, real PostgreSQL and browser tests | Synthetic metadata subset; no live EHR stream or full FHIR conformance |
| Edit configuration and rerun | Per-case bounded thresholds, same retained source, immutable report/delta | Denial-streak control needs explicit denial semantics unavailable in the current R4 mapping |
| Evidence and exports | Original/normalized events, related links, uncertainty, versions/hashes and canonical checksum | No signed attestation, anonymization or externally tamper-proof custody |
| Authentication and organization scope | Actual password/JWT/DB principal/role/org gates | Trusted local host/DB; no SSO or public deployment approval |
| Failure/recovery | Bounded actual body receive, atomic rollback, stale-run conflict, saved-case reload/restart and stale UI guards | No hard parser/worker kill deadline, coordinated quotas or tested production backup/restore |
| Separate NDJSON/automotive/ATT&CK paths | Source validation, supplied-event rules, CAN parser, source heuristics and ELF structures | Not real collectors, EDR/prevention, firmware execution/disassembly or live vehicle testing |

## Evidence method

Run every applicable suite after candidate freeze; identify prerequisites and individual skips. Fresh results belong to that exact commit. Prior implementation source `8ae9090b560871d1e584d717734693bb570fffae` and dated 68/116/212/280-test reports remain separate snapshots. Source-content hashes help compare implementation bytes but do not turn old runs into new-head execution. See [EVIDENCE.md](docs/EVIDENCE.md) and [documentation audit](docs/DOCUMENTATION_AUDIT.md).

The committed mixed-telemetry corpus uses a deterministic minimal ATT&CK index for fast rule regression; the full integration requires the pinned core and verified v19.2 bundles. Neither that corpus nor curated synthetic healthcare/CAN/firmware examples measures population precision/recall, clinical malicious-intent detection, hardware exploitability or customer adoption.

Release remains PARTIAL until the outstanding technical, hosted, documentary/external and deployment-specific gates are closed. No production/HIPAA approval, paid cloud service, live clinical/vehicle validation or automatic containment is established by this pass.
