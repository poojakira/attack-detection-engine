"""Non-executing ELF identification, not disassembly or firmware vulnerability assessment."""

import struct
from .base import DetectionFinding


class ARMBinaryAnalyzer:
    def detect(self, records: list[dict]) -> list[DetectionFinding]:
        findings = []
        for record in records:
            blob = record.get("binary")
            if not isinstance(blob, (bytes, bytearray)) or len(blob) > 32_000_000:
                raise ValueError("binary must be bytes within 32MB limit")
            if len(blob) < 52 or blob[:4] != b"\x7fELF":
                raise ValueError("expected complete ELF32 header")
            elf_class, endian = blob[4], blob[5]
            if elf_class != 1 or endian not in (1, 2) or blob[6] != 1:
                raise ValueError("unsupported ELF class/data/version")
            fmt = "<" if endian == 1 else ">"
            machine = struct.unpack_from(fmt + "H", blob, 18)[0]
            if machine != 40:
                raise ValueError("ELF is not ARM machine type")
            e_ehsize = struct.unpack_from(fmt + "H", blob, 40)[0]
            if e_ehsize != 52:
                raise ValueError("invalid ELF header size")
            # Evidence-only informational finding: architecture identification is not a CVE.
            findings.append(
                DetectionFinding(
                    rule_id="ARM-ELF-INFO",
                    rule_name="ARM ELF32 firmware identified",
                    severity="INFO",
                    confidence=1.0,
                    source_type="arm_binary",
                    raw_evidence={
                        "file_path": record.get("file_path", ""),
                        "machine": 40,
                        "endianness": "little" if endian == 1 else "big",
                    },
                    mappings=[],
                    description="ELF ARM header recognized; no disassembly or exploit assessment performed",
                )
            )
        return findings
