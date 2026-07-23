# attack-detection-engine

[![CI](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/poojakira/attack-detection-engine/actions/workflows/ci.yml)
[![Python >=3.10](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Unified detection engine mapping telemetry to MITRE ATT&CK v19 techniques across 5 data sources.

## Data Sources

| Source | Detector | Key Techniques |
|--------|----------|----------------|
| Logs (Windows, Linux, Cloud) | `LogDetector` | T1003, T1021, T1047, T1053, T1059, T1070, T1078, T1082, T1083, T1105, T1136, T1543, T1562, T1566 |
| Network (Zeek, Suricata, NetFlow) | `TrafficDetector` | T1041, T1043, T1048, T1071, T1090, T1095, T1102, T1205, T1219, T1498, T1571, T1572, T1590 |
| Behavior (Process trees, APIs) | `BehaviorDetector` | T1055, T1059, T1106 |
| EDR/SIEM Events | `EventDetector` | T1003, T1562, vendor-mapped |
| Static Code | `CodeDetector` | T1027, T1036, T1059, T1202, T1218, T1222, T1497, T1553, T1620 |

## Usage

```python
from attack_core import ATTACKLoader, ATTACKIndex
from detection_engine import DetectionPipeline

loader = ATTACKLoader()
index = ATTACKIndex(loader)
pipeline = DetectionPipeline(index)

telemetry = {
    "logs": [{"event_id": 4688, "message": "powershell.exe -enc ...", "host": "HOST1", ...}],
    "traffic": [{"record_type": "dns", "query": "longrandomstring.c2.com", ...}],
    "behaviors": [{"process_tree": {...}, "api_calls": [...]}],
    "events": [{"source": "crowdstrike", "event": {...}}],
    "code": [{"source_code": "eval(base64.b64decode(...))", "language": "python"}],
}

findings = pipeline.run(telemetry)
for f in findings:
    print(f"{f.rule_name} [{f.severity}] -> {[m.technique_id for m in f.mappings]}")

# Export for ATT&CK Navigator
serialized = pipeline.run_and_serialize(telemetry)
```

## Pipeline Output

Each finding includes:
- `rule_id`, `rule_name`, `severity`, `confidence`
- `source_type`: log/traffic/behavior/event/code
- `attack_mappings`: List of ATT&CKMapping objects
- `evidence`: Raw telemetry that triggered the rule

## Testing

```bash
pytest tests/ -v
```