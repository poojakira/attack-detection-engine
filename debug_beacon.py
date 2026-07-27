import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORE = ROOT.parent / "attack-v19-core"
if CORE.exists():
    sys.path.insert(0, str(CORE))
sys.path.insert(0, str(ROOT))

from attack_core import ATTACKIndex, ATTACKLoader  # noqa: E402
from detection_engine import DetectionPipeline  # noqa: E402

loader = ATTACKLoader()
index = ATTACKIndex(loader)
pipeline = DetectionPipeline(index)

traffic = []
base_ts = 1704067200.0
for i in range(15):
    traffic.append(
        {
            "record_type": "conn",
            "src_ip": "10.0.0.5",
            "dst_ip": "1.2.3.4",
            "dst_port": 443,
            "proto": "tcp",
            "bytes_out": 1024,
            "bytes_in": 512,
            "duration": 0.1,
            "timestamp": base_ts + i * 60.0,
        }
    )

findings = pipeline.run({"traffic": traffic})
print(f"Total findings: {len(findings)}")
for finding in findings:
    print(f"  {finding.rule_name} -> {[mapping.technique_id for mapping in finding.mappings]}")
