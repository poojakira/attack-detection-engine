"""Language-scoped static security heuristics; not a parser or compliance auditor.

Only locations and rule metadata leave this module. Source lines and potential PHI
values are never included in findings. Rules flag review candidates, not exploits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any

MAX_SOURCE_CHARS = 1_000_000
MAX_FINDINGS_PER_RECORD = 100

LANGUAGE_ALIASES = {
    "rb": "ruby", "ruby": "ruby",
    "golang": "go", "go": "go",
    "swift": "swift", "plist": "swift",
    "java": "java",
    "csharp": "dotnet", "c#": "dotnet", "cs": "dotnet", "dotnet": "dotnet",
    ".net": "dotnet", "asp.net": "dotnet",
}
EXTENSIONS = {".rb": "ruby", ".go": "go", ".swift": "swift",
              ".plist": "swift", ".java": "java", ".cs": "dotnet"}


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    language: str
    name: str
    expression: str
    severity: str
    cwe: str
    recommendation: str
    confidence: float = 0.80


RULES = (
    SecurityRule("XL-RUBY-001", "ruby", "Ruby TLS verification disabled",
                 r"OpenSSL::SSL::VERIFY_NONE", "HIGH", "CWE-295",
                 "Enable peer certificate verification."),
    SecurityRule("XL-RUBY-002", "ruby", "Ruby unsafe object deserialization",
                 r"\bMarshal\.load\s*\(", "HIGH", "CWE-502",
                 "Avoid Marshal.load on untrusted input; use a safe data format."),
    SecurityRule("XL-RUBY-003", "ruby", "Ruby request-driven command execution",
                 r"\b(?:system|exec)\s*\(\s*(?:params\[|request\.params)",
                 "CRITICAL", "CWE-78", "Remove shell execution of request-controlled input.", 0.93),
    SecurityRule("XL-GO-001", "go", "Go TLS verification bypass",
                 r"\bInsecureSkipVerify\s*:\s*true\b", "HIGH", "CWE-295",
                 "Keep certificate validation enabled."),
    SecurityRule("XL-GO-002", "go", "Go request-driven process execution",
                 r"\bexec\.Command(?:Context)?\s*\([^\n]*(?:r\.URL\.Query\(\)|r\.FormValue\s*\()",
                 "CRITICAL", "CWE-78", "Do not pass request values to a process launcher.", 0.92),
    SecurityRule("XL-GO-003", "go", "Go legacy TLS minimum",
                 r"\bMinVersion\s*:\s*tls\.VersionTLS1[01]\b", "MEDIUM", "CWE-326",
                 "Require a modern TLS minimum version."),
    SecurityRule("XL-SWIFT-001", "swift", "Swift insecure ATS configuration",
                 r"NSAllowsArbitraryLoads\s*(?:</key>\s*<true\s*/>|[:=]\s*true)",
                 "HIGH", "CWE-319", "Restrict App Transport Security exceptions."),
    SecurityRule("XL-SWIFT-002", "swift", "Swift token in UserDefaults",
                 r"\bUserDefaults\.standard\.set\s*\([^\n]*forKey\s*:\s*[\"'](?:accessToken|refreshToken|authToken)[\"']",
                 "HIGH", "CWE-922", "Store authentication tokens in Keychain."),
    SecurityRule("XL-SWIFT-003", "swift", "Swift explicit TLS trust exception",
                 r"\bSecTrustSetExceptions\s*\(", "MEDIUM", "CWE-295",
                 "Review trust exceptions and validate server identity."),
    SecurityRule("XL-JAVA-001", "java", "Java native deserialization",
                 r"\bnew\s+ObjectInputStream\s*\(", "HIGH", "CWE-502",
                 "Use safe formats or enforce an ObjectInputFilter."),
    SecurityRule("XL-JAVA-002", "java", "Java request-driven process execution",
                 r"\bRuntime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter\s*\(",
                 "CRITICAL", "CWE-78", "Remove request input from Runtime.exec."),
    SecurityRule("XL-JAVA-003", "java", "Java insecure hostname verifier",
                 r"\bsetHostnameVerifier\s*\([^\n]*(?:->\s*true|ALLOW_ALL_HOSTNAME_VERIFIER)",
                 "HIGH", "CWE-295", "Validate hostnames in TLS connections."),
    SecurityRule("XL-DOTNET-001", "dotnet", ".NET BinaryFormatter deserialization",
                 r"\b(?:new\s+)?BinaryFormatter\s*\(", "HIGH", "CWE-502",
                 "Replace BinaryFormatter with safer serializers."),
    SecurityRule("XL-DOTNET-002", "dotnet", ".NET request-driven process execution",
                 r"\bProcess\.Start\s*\(\s*(?:Request\.(?:QueryString|Form)|HttpContext\.Current\.Request)",
                 "CRITICAL", "CWE-78", "Do not launch processes with request data."),
    SecurityRule("XL-DOTNET-003", "dotnet", ".NET server certificate validation bypass",
                 r"\bServerCertificateValidationCallback\s*(?:\+?=)\s*[^\n]*=>\s*true\b",
                 "HIGH", "CWE-295", "Verify peer certificates, including hostnames."),
)

# Field names in a logging call suggest a PHI exposure risk; no real PHI is needed.
_PHI_LOG = re.compile(
    r"\b(?:Rails\.logger|logger|log|logging|System\.out|Console|fmt)\."
    r"(?:debug|info|warn|warning|error|print|println|Printf|Println|WriteLine)\s*\("
    r"[^\n]{0,400}\b(?:ssn|patient_id|patientName|medical_record|"
    r"diagnosis|dob|date_of_birth|prescription|getSSN\s*\()"
    r"|\bprint\s*\([^\n]{0,400}\b(?:ssn|patient_id|diagnosis|medical_record)\b",
    re.IGNORECASE,
)
_COMMENT_START = ("#", "//", "*", "/*", "<!--", "--")
_COMPILED = [(rule, re.compile(rule.expression, re.IGNORECASE | re.MULTILINE))
             for rule in RULES]


def detect_language(record: dict[str, Any]) -> str | None:
    declared = str(record.get("language") or "").lower().strip()
    if declared:
        return LANGUAGE_ALIASES.get(declared)
    return EXTENSIONS.get(PurePath(str(record.get("file_path") or "")).suffix.lower())


def _location(text: str, offset: int) -> tuple[int, int]:
    line_no = text.count("\n", 0, offset) + 1
    column = offset - text.rfind("\n", 0, offset)
    return line_no, column


def _in_comment(text: str, offset: int) -> bool:
    line = text[text.rfind("\n", 0, offset) + 1:offset].lstrip()
    return any(line.startswith(prefix) for prefix in _COMMENT_START)


def scan_code(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Bounded lexical security triage; matches require human confirmation.

    Oversized records fail closed rather than silently yielding partial results.
    """
    source = record.get("source_code")
    if not isinstance(source, str):
        raise TypeError("source_code must be a string")
    if len(source) > MAX_SOURCE_CHARS:
        raise ValueError("source_code exceeds maximum supported length")
    language = detect_language(record)
    if language is None or not source:
        return []
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    def add(rule_id: str, name: str, severity: str, confidence: float,
            cwe: str, recommendation: str, offset: int, privacy: bool = False) -> None:
        line, column = _location(source, offset)
        if (rule_id, line) in seen or _in_comment(source, offset):
            return
        seen.add((rule_id, line))
        results.append({
            "rule_id": rule_id, "rule_name": name, "severity": severity,
            "confidence": confidence, "cwe_id": cwe, "language": language,
            "line": line, "column": column, "file_path": str(record.get("file_path") or ""),
            "recommendation": recommendation, "hipaa_relevant": privacy,
        })

    for rule, matcher in _COMPILED:
        if rule.language != language:
            continue
        for match in matcher.finditer(source):
            add(rule.rule_id, rule.name, rule.severity, rule.confidence,
                rule.cwe, rule.recommendation, match.start())
            if len(results) >= MAX_FINDINGS_PER_RECORD:
                return results

    for match in _PHI_LOG.finditer(source):
        add("XL-PHI-001", "Potential PHI field in application logs", "HIGH", 0.75,
            "CWE-532", "Avoid logging PHI; review retention and access controls.",
            match.start(), privacy=True)
        if len(results) >= MAX_FINDINGS_PER_RECORD:
            break
    return results
