"""Conservative source-level firmware audit for supplied C/C++ text.

Heuristics only: findings require source review and are not proof of exploitability.
"""

import re
from .base import DetectionFinding


class FirmwareAuditor:
    CHECKS = (
        (
            "FW-C-001",
            "Potential unsafe C string copy",
            "HIGH",
            "CWE-120",
            r"\b(?:strcpy|strcat|gets)\s*\(",
        ),
        (
            "FW-C-002",
            "Potential unbounded formatted input",
            "HIGH",
            "CWE-120",
            r"\bscanf\s*\(\s*\"[^\"]*%s",
        ),
        (
            "FW-C-003",
            "Potential unsafe formatted output",
            "MEDIUM",
            "CWE-134",
            r"\bprintf\s*\(\s*[A-Za-z_]\w*\s*\)",
        ),
    )

    def detect(self, records: list[dict]) -> list[DetectionFinding]:
        findings = []
        for record in records:
            source = record.get("source_code")
            language = record.get("language")
            if not isinstance(source, str) or language not in ("c", "cpp", "c++"):
                raise ValueError(
                    "firmware requires source_code string and language c/cpp/c++"
                )
            if len(source) > 2_000_000:
                raise ValueError("firmware source exceeds offline audit limit")
            for rule_id, title, severity, cwe, regex in self.CHECKS:
                for match in re.finditer(regex, source):
                    line = source.count("\n", 0, match.start()) + 1
                    findings.append(
                        DetectionFinding(
                            rule_id=rule_id,
                            rule_name=title,
                            severity=severity,
                            confidence=0.6,
                            source_type="firmware",
                            raw_evidence={
                                "file_path": record.get("file_path", ""),
                                "line": line,
                                "cwe": cwe,
                                "matched_text": match.group()[:100],
                            },
                            mappings=[],
                            description=f"Review {cwe} candidate at line {line}; heuristic only",
                        )
                    )
        return findings
