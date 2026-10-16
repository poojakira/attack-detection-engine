"""Isolated tests: no vehicle hardware, CAN transmission or binary execution."""

import struct
import pytest
from detection_engine.automotive_can_detector import AutomotiveCANDetector
from detection_engine.firmware_auditor import FirmwareAuditor
from detection_engine.arm_binary_analyzer import ARMBinaryAnalyzer


@pytest.mark.parametrize("bad", [-1, 0x800, 0x20000000, True, "100"])
def test_invalid_can_ids(bad):
    with pytest.raises(ValueError):
        AutomotiveCANDetector(None).detect(
            [{"arbitration_id": bad, "timestamp": 0, "data": []}]
        )


def test_extended_can_and_can_fd():
    out = AutomotiveCANDetector(None).detect(
        [
            {
                "arbitration_id": 0x1FFFFFFF,
                "is_extended_id": True,
                "is_fd": True,
                "timestamp": 0,
                "data": [0] * 64,
            }
        ]
    )
    assert out == []


@pytest.mark.parametrize("bad", [[256], [-1], list(range(9)), "ff"])
def test_rejects_bad_payload(bad):
    with pytest.raises(ValueError):
        AutomotiveCANDetector(None).detect(
            [{"arbitration_id": 42, "timestamp": 0, "data": bad}]
        )


def test_can_policy_findings():
    records = [
        {
            "arbitration_id": 0x100,
            "timestamp": n / 100,
            "data": [1],
            "allowed_ids": [0x200],
            "max_frames_per_second": 2,
        }
        for n in range(4)
    ]
    rules = {x.rule_id for x in AutomotiveCANDetector(None).detect(records)}
    assert rules == {"CAN-ID-001", "CAN-RATE-001"}


@pytest.mark.parametrize("stamp", [float("nan"), float("inf"), None, "1"])
def test_bad_timestamp(stamp):
    with pytest.raises(ValueError):
        AutomotiveCANDetector(None).detect(
            [{"arbitration_id": 1, "timestamp": stamp, "data": []}]
        )


def test_firmware_findings_and_clean_case():
    audit = FirmwareAuditor()
    data = [
        {
            "language": "c",
            "source_code": "void f(char*a,char*b){strcpy(a,b);}\n",
            "file_path": "ecu.c",
        }
    ]
    hits = audit.detect(data)
    assert len(hits) == 1 and hits[0].raw_evidence["cwe"] == "CWE-120"
    assert hits[0].raw_evidence["line"] == 1
    assert (
        audit.detect([{"language": "c", "source_code": "int main(void){return 0;}"}])
        == []
    )


def test_arm_elf_identification():
    blob = bytearray(52)
    blob[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<H", blob, 18, 40)
    struct.pack_into("<H", blob, 40, 52)
    assert (
        ARMBinaryAnalyzer().detect([{"binary": bytes(blob)}])[0].rule_id
        == "ARM-ELF-INFO"
    )
    blob[18] = 3
    with pytest.raises(ValueError):
        ARMBinaryAnalyzer().detect([{"binary": bytes(blob)}])
