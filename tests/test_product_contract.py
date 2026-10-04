import pytest
from attack_v19_core import ATTACKIndex, ATTACKLoader

from detection_engine import DetectionPipeline


@pytest.fixture
def pipeline():
    return DetectionPipeline(ATTACKIndex(ATTACKLoader()))


def test_rejects_unknown_telemetry_source(pipeline):
    with pytest.raises(ValueError, match="unsupported telemetry source"):
        pipeline.run({"cloudtrail_raw": [{"eventName": "AssumeRole"}]})


def test_rejects_non_list_source(pipeline):
    with pytest.raises(TypeError, match="must contain a list"):
        pipeline.run({"logs": {"event_id": 4688}})


def test_rejects_non_object_record(pipeline):
    with pytest.raises(TypeError, match="non-object record"):
        pipeline.run({"events": ["raw string event"]})


def test_rejects_unbounded_batch():
    pipeline = DetectionPipeline(ATTACKIndex(ATTACKLoader()), max_records_per_source=2)
    with pytest.raises(ValueError, match="exceeds max_records_per_source"):
        pipeline.run({"logs": [{}, {}, {}]})


def test_mixed_sysmon_and_zeek_style_batch_is_detected(pipeline):
    telemetry = {
        "logs": [
            {
                "event_id": 4688,
                "message": "powershell.exe -enc SGVsbG8=",
                "host": "WIN-ENG-01",
                "timestamp": "2026-10-03T12:00:00Z",
                "source_type": "windows",
                "fields": {
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "ParentImage": r"C:\Windows\explorer.exe",
                },
            }
        ],
        "traffic": [
            {
                "record_type": "conn",
                "src_ip": "10.10.4.22",
                "dst_ip": "203.0.113.10",
                "dst_port": 443,
                "proto": "tcp",
                "bytes_out": 2048,
                "bytes_in": 256,
                "duration": 0.15,
                "timestamp": 1700000000.0 + i * 60.0,
            }
            for i in range(15)
        ],
    }

    findings = pipeline.run(telemetry)
    mapped = {
        mapping.technique_id
        for finding in findings
        for mapping in finding.mappings
    }
    assert any(value.startswith("T1059") for value in mapped)
    assert any(value.startswith("T1071") for value in mapped)
