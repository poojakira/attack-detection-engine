# attack-detection-engine

[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-View-blue)](https://poojakira.github.io/attack-detection-engine/)

[![CI](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml)
[![Python >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

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
from attack_core import ATTACKLoader, ATTACKIndex
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

You can omit any key you don't have data for. The pipeline only runs detectors for keys present in the dict.

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
make test       # pytest (27 tests)
make build      # build wheel
make security   # bandit + pip-audit
make verify     # all of the above in sequence
```

## Tests

There are 27 tests across 2 test files:
- `tests/test_pipeline.py` — integration tests that pass telemetry through the pipeline and verify detections fire for powershell, credential dumping, beaconing, DNS tunneling, code eval, and serialization
- `tests/test_revoked_id_handling.py` — tests that revoked ATT&CK technique IDs are correctly remapped

## CI Security Gate

CI runs Bandit against the `detection_engine` package, audits dependencies with pip-audit, and generates a CycloneDX SBOM. Results are uploaded as workflow artifacts. The build fails on medium/high Bandit findings or dependency vulnerabilities unless explicitly allowlisted in `.github/security-allowlist.json`.

## License

MIT
