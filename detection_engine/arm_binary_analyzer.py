"""Bounded, offline ARM ELF32 firmware analysis.

Reads program headers, permissions and entry-point placement. Does not disassemble
instructions, execute firmware, or claim to identify all firmware vulnerabilities.
"""

from __future__ import annotations

import hashlib
import struct

from .base import DetectionFinding


class ARMBinaryAnalyzer:
    MAX_FILE_SIZE = 32_000_000

    def detect(self, records: list[dict]) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        for record in records:
            blob = record.get("binary")
            if (
                not isinstance(blob, (bytes, bytearray))
                or not 52 <= len(blob) <= self.MAX_FILE_SIZE
            ):
                raise ValueError("expected ELF32 bytes (52 bytes to 32MB)")
            if (
                blob[:4] != b"\x7fELF"
                or blob[4] != 1
                or blob[5] not in (1, 2)
                or blob[6] != 1
            ):
                raise ValueError(
                    "unsupported ELF magic, 32-bit class, endianness or version"
                )
            fmt = "<" if blob[5] == 1 else ">"
            machine = struct.unpack_from(fmt + "H", blob, 18)[0]
            if machine != 40:
                raise ValueError("ELF is not ARM (EM_ARM=40)")
            entry = struct.unpack_from(fmt + "I", blob, 24)[0]
            phoff = struct.unpack_from(fmt + "I", blob, 28)[0]
            ehsize, phentsize, phnum = struct.unpack_from(fmt + "HHH", blob, 40)
            if ehsize != 52 or phnum > 128:
                raise ValueError(
                    "unsupported ELF header size / excessive program headers"
                )
            if phnum and (
                phentsize != 32 or phoff < 52 or phoff + phnum * phentsize > len(blob)
            ):
                raise ValueError("truncated or invalid ELF program header table")
            sha256 = hashlib.sha256(blob).hexdigest()
            evidence = {
                "file_path": record.get("file_path", ""),
                "machine": 40,
                "endianness": "little" if blob[5] == 1 else "big",
                "entry_point": entry,
                "sha256": sha256,
            }
            findings.append(
                self._finding(
                    "ARM-ELF-INFO",
                    "ARM ELF32 firmware identified",
                    "INFO",
                    evidence,
                    "ARM ELF32 structural evidence; not vulnerability proof",
                )
            )
            exec_ranges: list[tuple[int, int]] = []
            loads = 0
            for i in range(phnum):
                ph = struct.unpack_from(fmt + "IIIIIIII", blob, phoff + 32 * i)
                p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = ph
                if p_type == 1:  # PT_LOAD
                    loads += 1
                    if p_filesz > p_memsz or p_offset + p_filesz > len(blob):
                        raise ValueError("invalid or truncated loadable ELF segment")
                    if p_flags & 1:
                        exec_ranges.append((p_vaddr, p_vaddr + p_memsz))
                    if p_flags & 3 == 3:
                        findings.append(
                            self._finding(
                                "ARM-ELF-WX",
                                "Writable executable firmware segment",
                                "MEDIUM",
                                {
                                    **evidence,
                                    "segment": i,
                                    "flags": p_flags,
                                    "cwe": "CWE-732",
                                },
                                "PT_LOAD permits write and execute; review MPU/loader permissions",
                            )
                        )
                elif p_type == 0x6474E551 and (p_flags & 1):  # PT_GNU_STACK
                    findings.append(
                        self._finding(
                            "ARM-ELF-EXECSTACK",
                            "Executable stack requested",
                            "MEDIUM",
                            {
                                **evidence,
                                "segment": i,
                                "flags": p_flags,
                                "cwe": "CWE-732",
                            },
                            "ELF GNU_STACK requests executable memory; review target loader",
                        )
                    )
            if loads and not any(lo <= (entry & ~1) < hi for lo, hi in exec_ranges):
                findings.append(
                    self._finding(
                        "ARM-ELF-ENTRY",
                        "Entry outside executable load segment",
                        "LOW",
                        evidence,
                        "ELF entry does not fall inside a PT_LOAD executable range",
                    )
                )
        return findings

    @staticmethod
    def _finding(
        rule: str, name: str, severity: str, evidence: dict, desc: str
    ) -> DetectionFinding:
        return DetectionFinding(
            rule_id=rule,
            rule_name=name,
            severity=severity,
            confidence=1.0,
            source_type="arm_binary",
            raw_evidence=evidence,
            mappings=[],
            description=desc,
        )
