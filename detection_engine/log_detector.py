"""
Detects ATT&CK techniques from structured log records.

Supported log types:
  - Windows Event Log (EVTX / JSON export)
  - Linux auditd
  - macOS Unified Log
  - AWS CloudTrail
  - Azure Activity Log
  - GCP Cloud Audit Log
  - Syslog (RFC 5424)

Detection approach:
  1. Normalize log record to canonical schema (timestamp, host, source, event_id, message, fields)
  2. Apply keyword, regex, and field-match rules from pattern_library
  3. For each matching rule, build DetectionFinding with ATT&CKMapping

Key technique coverage (implement all):
  T1003   - OS Credential Dumping (event_id 4624, lsass access)
  T1021   - Remote Services (event_id 4648, RDP, WMI)
  T1047   - Windows Management Instrumentation
  T1053   - Scheduled Task/Job (event_id 4698/4702, cron)
  T1059   - Command and Scripting Interpreter (powershell, cmd, bash, python)
  T1070   - Indicator Removal (event_id 1102, auditd log deletion)
  T1078   - Valid Accounts (event_id 4625 repeated, then 4624)
  T1082   - System Information Discovery
  T1083   - File and Directory Discovery
  T1105   - Ingress Tool Transfer (curl/wget/bitsadmin in cmd)
  T1136   - Create Account (event_id 4720)
  T1543   - Create or Modify System Process (new service event_id 7045)
  T1562   - Impair Defenses (defender disabled, audit policy cleared)
  T1566   - Phishing (email header analysis)
  ... (all 222 techniques with available log data sources)
"""

import re
from typing import List, Any, Dict
from .base import BaseDetector, DetectionFinding
from .pattern_library import LOG_PATTERNS


class LogDetector(BaseDetector):
    def detect(self, data: List[Dict[str, Any]]) -> List[DetectionFinding]:
        """
        data: list of normalized log record dicts with keys:
              event_id, message, fields, source_type, timestamp, host
        """
        findings = []
        for record in data:
            for pattern in LOG_PATTERNS:
                if self._matches(record, pattern):
                    finding = DetectionFinding(
                        rule_id=pattern["rule_id"],
                        rule_name=pattern["rule_name"],
                        severity=pattern["severity"],
                        confidence=pattern["confidence"],
                        source_type="log",
                        raw_evidence=record,
                        mappings=[self._build_mapping(tid, pattern["confidence"])
                                  for tid in pattern["technique_ids"]],
                        timestamp=record.get("timestamp", ""),
                        host=record.get("host", ""),
                        description=pattern["description"],
                    )
                    findings.append(finding)
        return findings

    def _matches(self, record: Dict, pattern: Dict) -> bool:
        for condition in pattern.get("conditions", []):
            ctype = condition["type"]
            if ctype == "event_id":
                if str(record.get("event_id")) not in [str(e) for e in condition["values"]]:
                    return False
            elif ctype == "field_regex":
                field_val = str(record.get("fields", {}).get(condition["field"], ""))
                if not re.search(condition["pattern"], field_val, re.IGNORECASE):
                    return False
            elif ctype == "message_contains":
                if not any(kw.lower() in record.get("message", "").lower() for kw in condition["keywords"]):
                    return False
            elif ctype == "source_type":
                if record.get("source_type") not in condition["values"]:
                    return False
        return True