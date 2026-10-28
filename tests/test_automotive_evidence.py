"""Proof-oriented tests with a cross-compiled Cortex-M ELF committed as a fixture."""

from pathlib import Path
import struct
import pytest
from detection_engine.arm_binary_analyzer import ARMBinaryAnalyzer
from detection_engine.candump_parser import parse_candump_text
from detection_engine.automotive_can_detector import AutomotiveCANDetector
from detection_engine.firmware_auditor import FirmwareAuditor

ROOT = Path(__file__).resolve().parents[1]


def test_real_cross_compiled_cortexm_binary():
    binary = (ROOT / "examples/ecu/cortexm_lab.elf").read_bytes()
    result = ARMBinaryAnalyzer().detect(
        [{"binary": binary, "file_path": "cortexm_lab.elf"}]
    )
    ids = {f.rule_id for f in result}
    assert ids == {"ARM-ELF-INFO"}
    assert result[0].raw_evidence["sha256"]
    assert result[0].raw_evidence["entry_point"] & 1  # Thumb entry point


def test_writable_executable_segment_is_flagged():
    original = bytearray((ROOT / "examples/ecu/cortexm_lab.elf").read_bytes())
    phoff = struct.unpack_from("<I", original, 28)[0]
    struct.pack_into("<I", original, phoff + 24, 7)  # PF_R | PF_W | PF_X
    results = ARMBinaryAnalyzer().detect([{"binary": bytes(original)}])
    assert "ARM-ELF-WX" in {x.rule_id for x in results}


def test_executable_stack_segment_is_flagged():
    """A PT_GNU_STACK program header requesting execute permission must raise
    ARM-ELF-EXECSTACK (CWE-732). Builds on the real fixture by retyping its
    first program header to PT_GNU_STACK (0x6474E551) with PF_R|PF_X."""
    original = bytearray((ROOT / "examples/ecu/cortexm_lab.elf").read_bytes())
    phoff = struct.unpack_from("<I", original, 28)[0]
    struct.pack_into("<I", original, phoff + 0, 0x6474E551)  # p_type = PT_GNU_STACK
    struct.pack_into("<I", original, phoff + 24, 5)  # p_flags = PF_R | PF_X
    results = ARMBinaryAnalyzer().detect([{"binary": bytes(original)}])
    assert "ARM-ELF-EXECSTACK" in {x.rule_id for x in results}


def test_entry_point_outside_executable_segment_is_flagged():
    """If the ELF entry point does not fall inside any executable PT_LOAD
    range, the analyzer must raise ARM-ELF-ENTRY. We move the entry point far
    outside the fixture's single flash LOAD segment while keeping that segment
    executable so parsing still succeeds."""
    original = bytearray((ROOT / "examples/ecu/cortexm_lab.elf").read_bytes())
    struct.pack_into("<I", original, 24, 0x40000000)  # entry well outside flash LOAD
    results = ARMBinaryAnalyzer().detect([{"binary": bytes(original)}])
    assert "ARM-ELF-ENTRY" in {x.rule_id for x in results}


@pytest.mark.parametrize("tamper", ["truncated", "bad-header", "bad-segment"])
def test_corrupted_elf_rejected(tamper):
    binary = bytearray((ROOT / "examples/ecu/cortexm_lab.elf").read_bytes())
    if tamper == "truncated":
        binary = binary[:56]
    elif tamper == "bad-header":
        struct.pack_into("<H", binary, 42, 33)
    else:
        phoff = struct.unpack_from("<I", binary, 28)[0]
        struct.pack_into("<I", binary, phoff + 16, len(binary) + 1)
    with pytest.raises(ValueError):
        ARMBinaryAnalyzer().detect([{"binary": bytes(binary)}])


def test_real_candump_lab_traces():
    norm = parse_candump_text((ROOT / "examples/can/normal.candump").read_text())
    attack = parse_candump_text((ROOT / "examples/can/anomalous.candump").read_text())
    for frame in norm + attack:
        frame["allowed_ids"] = [0x123, 0x456]
        frame["max_frames_per_second"] = 3
    assert not AutomotiveCANDetector(None).detect(norm)
    ids = {f.rule_id for f in AutomotiveCANDetector(None).detect(attack)}
    assert ids == {"CAN-ID-001", "CAN-RATE-001"}


@pytest.mark.parametrize(
    "text",
    [
        "(1.0) vcan0 123#00F",
        "(1.0) vcan0 123#GG",
        "(1.0) vcan0 800#00",
        "(1.0) vcan0 123#001122334455667788",
    ],
)
def test_candump_bad_frames_rejected(text):
    with pytest.raises(ValueError):
        parse_candump_text(text)


def test_vulnerable_and_fixed_code_audit_differ():
    vulnerable = (ROOT / "examples/ecu/ecu_vulnerable.c").read_text()
    fixed = (ROOT / "examples/ecu/ecu_fixed.c").read_text()
    audit = FirmwareAuditor()
    assert any(
        f.raw_evidence["cwe"] == "CWE-120"
        for f in audit.detect([{"language": "c", "source_code": vulnerable}])
    )
    assert not audit.detect([{"language": "c", "source_code": fixed}])
