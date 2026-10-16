"""The new sources must function through the public DetectionPipeline."""

import struct
from unittest.mock import Mock

from detection_engine.pipeline import DetectionPipeline


def test_mixed_automotive_pipeline_end_to_end():
    index = Mock()
    index.get.return_value = None
    pipe = DetectionPipeline(index)
    elf = bytearray(52)
    elf[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<H", elf, 18, 40)
    struct.pack_into("<H", elf, 40, 52)
    results = pipe.run_and_serialize(
        {
            "automotive_can": [
                {
                    "arbitration_id": 10,
                    "timestamp": 1.0,
                    "data": [1],
                    "allowed_ids": [20],
                }
            ],
            "firmware": [
                {
                    "language": "c",
                    "file_path": "test.c",
                    "source_code": "void f(char*a,char*b){strcpy(a,b);}",
                }
            ],
            "arm_binary": [{"binary": bytes(elf), "file_path": "test.elf"}],
        }
    )
    assert {r["rule_id"] for r in results} == {"CAN-ID-001", "FW-C-001", "ARM-ELF-INFO"}
    assert all(r["attack_mappings"] == [] for r in results)
