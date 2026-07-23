import sys
sys.path.insert(0, '~/repos/attack-v19-core')
sys.path.insert(0, '~/repos/attack-detection-engine')

from attack_core import ATTACKLoader, ATTACKIndex
from detection_engine import DetectionPipeline

loader = ATTACKLoader()
index = ATTACKIndex(loader)
pipeline = DetectionPipeline(index)

traffic = []
base_ts = 1704067200.0
for i in range(15):
    traffic.append({
        "record_type": "conn",
        "src_ip": "10.0.0.5",
        "dst_ip": "1.2.3.4",
        "dst_port": 443,
        "proto": "tcp",
        "bytes_out": 1024,
        "bytes_in": 512,
        "duration": 0.1,
        "timestamp": base_ts + i * 60.0,
    })

findings = pipeline.run({"traffic": traffic})
print(f"Total findings: {len(findings)}")
for f in findings:
    print(f"  {f.rule_name} -> {[m.technique_id for m in f.mappings]}")