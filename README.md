# attack-detection-engine

**Repository owner & maintainer:** Pooja Kiran ([@poojakira](https://github.com/poojakira)) — I own and maintain this repository and drive its design, engineering, validation, documentation, and evidence-backed releases.

[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-View-blue)](https://poojakira.github.io/attack-detection-engine/)

[![CI](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml)
[![Python >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`attack-detection-engine` takes telemetry (logs, network traffic, process behavior, EDR events, or source code), checks it against a rule library, and returns findings mapped to MITRE ATT&CK v19 technique IDs (via `attack-v19-core`). It exists to turn heterogeneous telemetry into ATT&CK-mapped detections through a single pipeline with five input-specific detectors.

## Repository Evidence Snapshot

Hosted CI is intentionally manual-dispatch only for zero-cost operation, so the table below reports locally reproduced source/test evidence rather than implying an automatic hosted run.

| Metric | Current documented state |
|---|---:|
| Detectors | 5 (log, traffic, behavior, event, code) — verified: 5 detector modules present |
| ATT&CK mapping | v19 via `attack-v19-core` dependency |
| Detection rules | 42, reproduced directly from `detection_engine/pattern_library.py`: 15 log + 7 traffic + 3 behavior + 2 event + 5 code + 10 AI-specific patterns |

> The 42-rule count is source-reproduced without importing the sibling package; runtime ATT&CK-ID resolution still depends on the pinned `attack-v19-core` dependency.

## Security Problem

Security telemetry arrives in many formats — logs, netflow, process trees, EDR events, source code — and mapping each signal to a consistent threat taxonomy is manual and error-prone. This engine applies input-specific detectors and maps every match to an ATT&CK v19 technique, so heterogeneous telemetry produces a normalized, framework-aligned finding stream.

## Threat Model & Scope

**In scope:** rule-based detection over supplied telemetry, mapped to ATT&CK v19 techniques, across five input types.

**Out of scope / not claimed:** It is a detection/mapping engine over telemetry you provide; it is not a collection agent, EDR, or SIEM, and does not enforce. Detection is rule-based and only as complete as the 42-pattern library; a rule count is not a detection-rate or coverage guarantee.

## Architecture

```text
Telemetry dict {logs | traffic | behaviors | events | code}
      |
      v
DetectionPipeline.run()  -->  per-input detectors (Log/Traffic/Behavior/Event/Code)
      |
      v
Rule matches  -->  ATT&CK v19 technique mapping (attack-v19-core)  -->  findings
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

There are 5 detectors, each handling a different type of input:

| Detector | Input | What It Detects |
|----------|-------|-----------------|
| `LogDetector` | Windows/Linux event logs | Credential dumping (T1003), RDP logons (T1021), WMI execution (T1047), scheduled tasks (T1053), PowerShell/cmd execution (T1059), log clearing (T1685.005), brute force (T1078/T1110), discovery commands (T1082/T1083), tool download (T1105), account creation (T1136), service creation (T1543), Defender disabled (T1685), phishing indicators (T1566) |
| `TrafficDetector` | Network records (Zeek/Suricata/NetFlow style) | C2 beaconing (T1071), DNS tunneling (T1048), port anomalies (T1571), proxy/tunnel use (T1090/T1572), DDoS patterns (T1498) |
| `BehaviorDetector` | Process trees and API call sequences | Process injection (T1055), suspicious parent-child chains (T1059), API abuse (T1106) |
| `EventDetector` | EDR/SIEM events (CrowdStrike, etc.) | Credential access (T1003), defense impairment (T1562), plus vendor-specific event mappings |
| `CodeDetector` | Source code files | Obfuscated code (T1027), eval/exec patterns (T1059), masquerading (T1036), indirect execution (T1202), signed binary abuse (T1218), permission changes (T1222), sandbox evasion (T1497), code signing bypass (T1553), reflective loading (T1620) |

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

You can omit any supported key you do not have data for. Supported keys are exactly `logs`, `traffic`, `behaviors`, `events`, and `code`. Unknown source keys, non-list source values, non-object records, and batches above the configured per-source ceiling fail loudly instead of being silently ignored.

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
make test       # pytest (23 test functions, 29 cases with parametrization)
make build      # build wheel
make security   # bandit + pip-audit
make verify     # all of the above in sequence
```

## Tests

There are 23 test functions across 3 test files (pytest collects 29 cases because one test is parametrized):
- `tests/test_pipeline.py` (8) — integration tests that pass telemetry through the pipeline and verify detections fire for powershell, credential dumping, beaconing, DNS tunneling, code eval, and serialization
- `tests/test_revoked_id_handling.py` (13) — tests that revoked ATT&CK technique IDs are correctly remapped
- `tests/test_cli.py` (2) — tests that the CLI processes NDJSON input and rejects non-object records

## CI Security Gate

CI runs Bandit against the `detection_engine` package, audits dependencies with pip-audit, and generates a CycloneDX SBOM. Results are uploaded as workflow artifacts. The build fails on medium/high Bandit findings or dependency vulnerabilities unless explicitly allowlisted in `.github/security-allowlist.json`.

## License

MIT

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
