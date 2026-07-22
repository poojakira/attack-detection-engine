"""
Static code analysis detection engine.
Analyzes: Python, PowerShell, Bash, JavaScript, C/C++, Go, Rust
"""

import re
from typing import List, Dict, Any
from .base import BaseDetector, DetectionFinding
from .pattern_library import CODE_PATTERNS


class CodeDetector(BaseDetector):
    def __init__(self, index):
        super().__init__(index)
        self._patterns = [self._compile_pattern(p) for p in CODE_PATTERNS]

    def _compile_pattern(self, pattern: Dict) -> Dict:
        compiled = pattern.copy()
        if pattern.get("pattern"):
            try:
                compiled["regex"] = re.compile(pattern["pattern"], re.IGNORECASE | re.MULTILINE)
            except re.error:
                compiled["regex"] = None
        return compiled

    def detect(self, data: List[Dict[str, Any]]) -> List[DetectionFinding]:
        """
        data: list of code analysis records with keys:
              - source_code: string
              - file_path: string
              - language: string
              - hash: string (optional)
        """
        findings = []
        for record in data:
            source = record.get("source_code", "")
            if not source:
                continue
            for pattern in self._patterns:
                if pattern.get("regex") and pattern["regex"].search(source):
                    findings.append(self._make_finding(pattern, record))
        return findings

    def _make_finding(self, pattern: Dict, record: Dict) -> DetectionFinding:
        matches = pattern["regex"].findall(record.get("source_code", "")) if pattern.get("regex") else []
        evidence = {
            "file_path": record.get("file_path", ""),
            "language": record.get("language", ""),
            "matches": matches[:10],
            "hash": record.get("hash", ""),
        }
        return DetectionFinding(
            rule_id=pattern["rule_id"],
            rule_name=pattern["rule_name"],
            severity=pattern["severity"],
            confidence=pattern["confidence"],
            source_type="code",
            raw_evidence=evidence,
            mappings=[self._build_mapping(tid, pattern["confidence"]) for tid in pattern["technique_ids"]],
            timestamp=record.get("timestamp", ""),
            host=record.get("host", ""),
            description=f"{pattern['description']} in {record.get('file_path', 'unknown')}",
        )