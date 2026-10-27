> **READ THIS LICENSE BEFORE COPYING, USING, OR MODIFYING ANY MATERIAL.** This repository's owner-controlled original content is proprietary and **All Rights Reserved**. There is no permission to copy, modify, distribute, or reuse it without prior written authorization, subject to existing third-party rights, any prior valid licenses, GitHub's Terms, and applicable law. See [LICENSE](LICENSE).

# attack-detection-engine

**Repository owner & maintainer:** Pooja Kiran ([@poojakira](https://github.com/poojakira)) — I own and maintain this repository and drive its design, engineering, validation, documentation, and evidence-backed releases.

[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-View-blue)](https://poojakira.github.io/attack-detection-engine/)

[![CI](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml)
[![Python >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

## Overview

`attack-detection-engine` takes telemetry (logs, network traffic, process behavior, EDR events, source code, and offline automotive/embedded lab inputs), checks it against a rule library, and returns findings mapped to MITRE ATT&CK v19 technique IDs (via `attack-v19-core`). It exists to turn heterogeneous telemetry into ATT&CK-mapped detections through a single pipeline with five original ATT&CK-oriented detectors and three separate offline lab analysis sources.

## Repository Evidence Snapshot

Hosted CI is intentionally manual-dispatch only for zero-cost operation, so the table below reports locally reproduced source/test evidence rather than implying an automatic hosted run.

| Metric | Current documented state |
|---|---:|
| Original ATT&CK-oriented detectors | 5 (log, traffic, behavior, event, code) — verified: 5 detector modules present |
| ATT&CK mapping | v19 via `attack-v19-core` dependency |
| Detection rules | 42, reproduced directly from `detection_engine/pattern_library.py`: 15 log + 7 traffic + 3 behavior + 2 event + 5 code + 10 AI-specific patterns |

> The 42-rule count is source-reproduced without importing the sibling package; runtime ATT&CK-ID resolution still depends on the pinned `attack-v19-core` dependency.

## Security Problem

Security telemetry arrives in many formats — logs, netflow, process trees, EDR events, source code — and mapping each signal to a consistent threat taxonomy is manual and error-prone. This engine applies input-specific detectors and maps every match to an ATT&CK v19 technique, so heterogeneous telemetry produces a normalized, framework-aligned finding stream.

## Threat Model & Scope

**In scope:** rule-based detection over supplied telemetry, mapped to ATT&CK v19 techniques, across eight accepted input types (five original telemetry sources and three offline lab sources).

**Out of scope / not claimed:** It is a detection/mapping engine over telemetry you provide; it is not a collection agent, EDR, or SIEM, and does not enforce. Detection is rule-based and only as complete as the 42-pattern library; a rule count is not a detection-rate or coverage guarantee.

## Architecture

```text
Telemetry dict {logs | traffic | behaviors | events | code | automotive_can | firmware | arm_binary}
      |
      v
DetectionPipeline.run()  -->  five ATT&CK detectors plus three offline security-analysis modules
      |
      v
Findings  -->  ATT&CK v19 when applicable; CWE evidence for some firmware findings
```

## Core Capabilities

- Five input-specific detectors: `LogDetector`, `TrafficDetector`, `BehaviorDetector`, `EventDetector`, `CodeDetector`
- Rule library mapped to MITRE ATT&CK v19 technique IDs
- Single `DetectionPipeline.run()` entry point over a strictly validated telemetry envelope
- ATT&CK lookups via the `attack-v19-core` sibling library

## What This Is

A detection engine that takes telemetry data (logs, network traffic, process behavior, EDR events, or source code) and checks it against a library of 42 detection rules. When a rule matches, the engine returns a finding mapped to a MITRE ATT&CK v19 technique ID.

It depends on `attack-v19-core` for ATT&CK technique lookups and mapping.

## Detectors

There are five original ATT&CK-oriented detectors and three additional offline lab analysis sources:

| Detector | Input | What It Detects |
|----------|-------|-----------------|
| `LogDetector` | Windows/Linux event logs | Credential dumping (T1003), RDP logons (T1021), WMI execution (T1047), scheduled tasks (T1053), PowerShell/cmd execution (T1059), log clearing (T1685.005), brute force (T1078/T1110), discovery commands (T1082/T1083), tool download (T1105), account creation (T1136), service creation (T1543), Defender disabled (T1685), phishing indicators (T1566) |
| `TrafficDetector` | Network records (Zeek/Suricata/NetFlow style) | C2 beaconing (T1071), DNS tunneling (T1048), port anomalies (T1571), proxy/tunnel use (T1090/T1572), DDoS patterns (T1498) |
| `BehaviorDetector` | Process trees and API call sequences | Process injection (T1055), suspicious parent-child chains (T1059), API abuse (T1106) |
| `EventDetector` | EDR/SIEM events (CrowdStrike, etc.) | Credential access (T1003), defense impairment (T1562), plus vendor-specific event mappings |
| `CodeDetector` | Source code files | Obfuscated code (T1027), eval/exec patterns (T1059), masquerading (T1036), indirect execution (T1202), signed binary abuse (T1218), permission changes (T1222), sandbox evasion (T1497), code signing bypass (T1553), reflective loading (T1620) |

### Additional offline embedded-security inputs (implemented October 2026)

| Input source | Implementation | Evidence and limitations |
|---|---|---|
| `automotive_can` | `AutomotiveCANDetector` checks decoded frame ID allowlists and per-ID rate limits | Synthetic timestamped candump fixtures only; no real bus capture, replay attribution, or live blocking |
| `firmware` | `FirmwareAuditor` flags selected C/C++ string and format hazards | Regex-based CWE *candidates*, not proof of exploitability or full static analysis |
| `arm_binary` | `ARMBinaryAnalyzer` checks ARM ELF32 structures and risky W+X/stack flags | Reproducible cross-compiled Cortex-M3 example; not instruction disassembly, real ECU extraction, or reverse engineering |

The extra sources keep the pipeline finding contract but **do not invent ATT&CK technique mappings** for unrelated firmware or CAN findings. See [AUTOMOTIVE_SECURITY.md](AUTOMOTIVE_SECURITY.md) for compiler commands, evidence fixtures, scoped assessment and repeatable tests.

### Healthcare clinical-access detection (added October 2026)

The engine also accepts a `clinical_access` source: a modular healthcare
detection component that shares the pipeline but is code-decoupled from the
automotive detectors (it lives under `detection_engine/healthcare/`).

| Component | What it does |
|---|---|
| `ClinicalAccessEvent` schema | Normalized, UTC, correlation-ready clinical-access event. PII-rejecting and `extra`-forbidden by design; carries pseudonymous identifiers and access metadata only — never patient record content. Includes a FHIR R4 `AuditEvent` normalizer. |
| `PatientAccessDetector` | Seven deterministic, explainable rules: bulk patient access, off-shift unassigned access, unassigned-access review, break-glass review, repeated-denial-then-success, service-account scope violation, and bulk export. Uses authorization context (assignments, scopes, shifts) so legitimate multi-patient and documented emergency access are **not** treated as malicious. |
| Synthetic generator | Seed-deterministic, clearly labeled **synthetic** benign and attack scenarios. Fictional — not real incidents, not derived from any patient dataset. |
| MIMIC-IV Demo adapter | Verifies the ODbL demo dataset against published SHA256 sums and derives *legitimate* provider→patient context from real admissions. De-identified clinical data is used only for benign context and is kept strictly separate from synthetic security events. |

ATT&CK is attached only where justified (bulk export → **T1567**); access-pattern
anomalies emit no invented mapping. This is a detection component, not a
compliance tool — **no HIPAA certification or production-readiness is claimed.**
See **[HEALTHCARE_SECURITY.md](HEALTHCARE_SECURITY.md)** for the rule table,
privacy properties, a runnable end-to-end example, limitations, and verified test
evidence, and **[PROVENANCE.md](PROVENANCE.md)** for MIMIC-IV attribution.

## How It Works

You pass a dictionary of telemetry to `DetectionPipeline.run()`. Each key corresponds to a detector:

```python
from attack_v19_core import ATTACKLoader, ATTACKIndex
from detection_engine import DetectionPipeline

loader = ATTACKLoader()
index = ATTACKIndex(loader)
pipeline = DetectionPipeline(index)

telemetry = {
    "logs": [{"event_id": 4688, "message": "powershell.exe -enc ...", "host": "HOST1", "timestamp": "...", "source_type": "windows", "fields": {"Image": "powershell.exe"}}],
    "traffic": [{"record_type": "dns", "query": "longrandomstring.c2.com", "src_ip": "10.0.0.5", "timestamp": 1000.0}],
    "behaviors": [{"process_tree": {}, "api_calls": []}],
    "events": [{"source": "crowdstrike", "event": {}}],
    "code": [{"source_code": "eval(base64.b64decode(...))", "language": "python"}],
}

findings = pipeline.run(telemetry)
for f in findings:
    print(f"{f.rule_name} [{f.severity}] -> {[m.technique_id for m in f.mappings]}")
```

You can omit any supported key you do not have data for. Supported keys are exactly `logs`, `traffic`, `behaviors`, `events`, `code`, `automotive_can`, `firmware`, `arm_binary`, and `clinical_access`. Unknown source keys, non-list source values, non-object records, and batches above the configured per-source ceiling fail loudly instead of being silently ignored.

## Output Format

Each finding contains:
- `rule_id` / `rule_name` — which rule triggered
- `severity` — CRITICAL, HIGH, MEDIUM, LOW, or INFO
- `confidence` — float between 0 and 1
- `source_type` — log, traffic, behavior, event, or code
- `mappings` — list of ATT&CK technique mappings (technique ID + confidence)
- `raw_evidence` — the input data that triggered the rule

Use `pipeline.run_and_serialize(telemetry)` to get dict output instead of dataclass objects.

## Install

Requires Python 3.10+.

```bash
pip install attack-detection-engine
```

Or from source:

```bash
git clone https://github.com/poojakira/attack-detection-engine
cd attack-detection-engine
make install
```

The `attack-v19-core` package must be available. If you're developing locally with the source repo, use `make install-core` to install it from the sibling directory.

## Development

```bash
make lint       # ruff check
make format     # ruff format
make test       # pytest; parametrized cases exceed source function counts
make build      # build wheel
make security   # bandit + pip-audit
make verify     # all of the above in sequence
```

## Tests

The current source declares 29 test functions across 5 test files. This is an AST count, not a collected or passing-test total:
- `tests/test_pipeline.py` (8) — integration tests that pass telemetry through the pipeline and verify detections fire for powershell, credential dumping, beaconing, DNS tunneling, code eval, and serialization
- `tests/test_revoked_id_handling.py` (13) — tests that revoked ATT&CK technique IDs are correctly remapped
- `tests/test_cli.py` (2) — tests that the CLI processes NDJSON input and rejects non-object records
- `tests/test_product_contract.py` (5) - telemetry validation and mixed-batch mapping against the pinned index
- `tests/test_product_telemetry_corpus.py` (1 parametrized function) - committed deterministic telemetry regression fixtures

## CI Security Gate

CI runs Bandit against the `detection_engine` package, audits dependencies with pip-audit, and generates a CycloneDX SBOM. Results are uploaded as workflow artifacts. The build fails on medium/high Bandit findings or dependency vulnerabilities unless explicitly allowlisted in `.github/security-allowlist.json`.

## License

Proprietary / All Rights Reserved. See [LICENSE](LICENSE).

<!-- repo-verification:start -->
## Verification update — 2026-09-30

- **Scope:** Account-wide `poojakira` repository pass covering source/configuration, CI/release workflows, security-hygiene gates, dependency/SAST controls, and documentation consistency.
- **Remediation:** Reviewed the engine’s pinned ATT&CK-core dependency, repository security gate, and release configuration.
- **Verification state:** Hosted Actions is currently blocked before runner assignment: the latest CI failure contained zero executed steps, so no lint, test, or repository-security step actually ran.
- **Security note:** Re-run CI after hosted-runner/account availability returns before changing the engine based on the current red badge.
- **Evidence boundary:** This update records repository and GitHub Actions evidence observed during the pass. It is not a claim of independent penetration testing, production deployment, or zero residual risk.
<!-- repo-verification:end -->

## Verification checkpoint — 2026-09-30

- **Snapshot commit:** `cd871b22a7ae6282539f9645fb9f9de1bd0bed02`
- **Status:** EXTERNAL ACTION REQUIRED
- **Evidence:** The GitHub Actions lint job failed before a runner was assigned (`runner_id: 0`) and executed zero steps; dependent test/security jobs were skipped. This is not verified evidence of a code failure.
- This checkpoint is intentionally date-bounded. It does not claim zero vulnerabilities or universal production readiness.


## Secret handling

Keep runtime credentials outside Git. If this repository provides an `.env.example` or `.env.sample`, copy it to a local `.env` or `.env.local` and fill in values locally; the real environment file must remain untracked.

Do not commit AWS access keys or session credentials, API tokens, service-account JSON, private keys, package-manager credentials, Terraform state, or secret-bearing `tfvars`. CI/deployment credentials belong in GitHub Actions secrets or the deployment provider's secret manager. AWS account IDs are identifiers; AWS access-key IDs, secret access keys, and session tokens are credentials.

If a real credential is ever exposed, revoke or rotate it at the provider first, then remove it from the working tree and reachable Git history. The Security Hygiene workflow checks the current tree and reachable history for common credential formats without printing matched secret values.

<!-- security-local-config:start -->
## Secrets and local configuration

- Never commit real API keys, access tokens, passwords, cloud credentials, private keys, or a populated `.env` file.
- Local `.env` and `.env.*` files are ignored by Git. Only safe templates such as `.env.example` or `.env.sample` may be committed, and they must contain placeholder or empty values only.
- If an integration needs credentials, create your own local `.env` file (or use your shell/secret manager) and supply **your own** API key. In GitHub Actions, use repository/environment secrets rather than hard-coding values in workflow YAML.
- Do not copy or reuse any credential that appears in repository history, examples, tests, screenshots, logs, or documentation. Test strings are not intended to be usable credentials.
- If a real credential is ever committed, **revoke or rotate it at the credential provider first**, then remove it from the current tree and reachable Git history. Deleting a key from GitHub does not revoke it.
<!-- security-local-config:end -->

## Cost-safe CI execution

This private repository keeps GitHub Actions workflows on manual workflow dispatch only so ordinary pushes, pull requests, schedules, and tags do not consume hosted-runner minutes unexpectedly.

Local validation is the default. To guarantee zero cost, do not dispatch hosted workflows unless the run is covered by a no-charge allowance or a self-hosted runner; no routine validation should provision cloud infrastructure, call paid external APIs, or publish containers/packages.

## Pilot validation corpus

A committed mixed-telemetry corpus exercises the real detection pipeline with Windows/Sysmon-like process records, Zeek/NetFlow-like periodic connection records, code telemetry, and an empty benign control. It is a deterministic mapping/regression check, **not** an enterprise detection-rate claim. See `PRODUCT_VALIDATION.md`.


## Verification snapshot — 2026-10-03

The committed mixed-telemetry pilot corpus completed **5/5 cases passing** after being separated from the slower full ATT&CK bundle integration path. Existing full-index contract tests remain the integration boundary for the pinned `attack-v19-core` dependency.


## Maintenance verification - October 9, 2026

Ruff 0.8.4 checked and format-checked all 18 available Python files; both passed after formatting maintained source, helper and test files. CI covers repository-wide Python discovery, and Makefile lint/format includes scripts.

Full ATT&CK integration tests were not run in this pass because the pinned sibling dependency/data were not installed. The 29 source test functions are static inventory, not a passing-test claim.

## October 15, 2026 post-merge automotive verification

On Windows Python 3.12, **29/29 focused automotive/embedded test cases passed**, Ruff lint passed, and pytest **collected 68 tests overall**. (Superseded by the October 17, 2026 entry below, which adds two regression tests: the focused subset is now 31/31 and the full suite collects 70.) The full historical suite is *not yet confirmed passing*. The firmware evidence includes a genuine ARM Cortex-M3 ELF cross-compiled using arm-none-eabi-gcc in WSL and an intentional C memory-safety lab defect reproduced with Clang AddressSanitizer and subsequently fixed. All security inputs were synthetic or locally authored; no real vehicle or production ECU was tested. See [AUTOMOTIVE_SECURITY.md](AUTOMOTIVE_SECURITY.md).

## Full-suite performance verification (October 15, 2026)

The complete repository suite passed **68/68 tests in 25.92 seconds** on Windows Python 3.12.13 after reusing a session-scoped ATT&CK index in the legacy integration fixtures. The test assertions remain unchanged. This is a local full-suite result, **not** a real-ECU hardware certification or a production effectiveness measurement.

## ARM ELF analyzer hardening and firmware CI (October 17, 2026)

Verified in a clean `python:3.11` + `gcc:13` Docker environment (numpy pinned `<2`, `attack-v19-core` installed, repository installed via `.[dev]`):

- **Two new regression tests** in `tests/test_automotive_evidence.py` cover previously-untested `ARMBinaryAnalyzer` detection paths: executable-stack (`ARM-ELF-EXECSTACK`, PT_GNU_STACK with PF_X) and entry-point-outside-executable-segment (`ARM-ELF-ENTRY`). The focused automotive/firmware/ARM subset now passes **31/31** (was 29/29); full-suite collection is **70 tests** (was 68). Coverage of `detection_engine/arm_binary_analyzer.py` rose from 88% to 94%.
- **Linker hardening** in `examples/ecu/linker.ld`: RAM region changed from `(rwx)` to `(rw)`. The fixture executes only from FLASH, so RAM needs no execute permission; this aligns the linker intent with a W^X policy and with the repository's own `ARM-ELF-WX` (CWE-732) detector. `arm-none-eabi-readelf -l` on the recompiled fixture confirms a FLASH `R E` segment and a RAM `RW` segment, with **no writable+executable (RWE)** segment. Machine `ARM`, Class `ELF32`, Thumb entry point.
- **New workflow** `.github/workflows/arm-firmware.yml` (manual dispatch): installs `arm-none-eabi-gcc`, cross-compiles `examples/ecu/cortexm_lab.c`, runs `readelf -h -S -l`, asserts ELF32 / ARM / no-RWE, uploads the ELF and readelf output as artifacts, and runs the offline automotive/firmware/ARM test subset. The workflow is hardware-independent and makes no claim of physical-hardware or emulator execution.

This is a local, Docker-reproducible result, **not** a real-ECU hardware certification or a production effectiveness measurement.
