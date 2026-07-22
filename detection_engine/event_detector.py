"""
EDR telemetry and SIEM event detection engine.
"""

from typing import List, Dict, Any
from collections import defaultdict, deque
from .base import BaseDetector, DetectionFinding
from .pattern_library import EVENT_PATTERNS


class EventDetector(BaseDetector):
    def __init__(self, index):
        super().__init__(index)
        self._auth_failures: Dict[str, deque] = defaultdict(lambda: deque(maxlen=50))
        self._process_creates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

    def detect(self, data: List[Dict[str, Any]]) -> List[DetectionFinding]:
        findings = []
        for record in data:
            source = record.get("source", "").lower()
            if "crowdstrike" in source or "falcon" in source:
                findings.extend(self._analyze_crowdstrike(record))
            elif "sentinelone" in source or "s1" in source:
                findings.extend(self._analyze_sentinelone(record))
            elif "defender" in source or "mde" in source:
                findings.extend(self._analyze_defender(record))
            elif "elastic" in source or "endgame" in source:
                findings.extend(self._analyze_elastic(record))
            else:
                findings.extend(self._analyze_generic_edr(record))
        return findings

    def _analyze_crowdstrike(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        event = record.get("event", {})
        event_type = event.get("event_type", "")
        tactic = event.get("tactic", "")
        technique = event.get("technique", "")

        if technique:
            findings.append(self._make_finding(
                technique, f"CrowdStrike: {event_type}",
                "HIGH", 0.9, record,
                f"CrowdStrike detection: {event_type} ({tactic})"
            ))

        return findings

    def _analyze_sentinelone(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        threat = record.get("threatInfo", {})
        mitre_attack = threat.get("mitreAttack", [])
        for attack in mitre_attack:
            technique = attack.get("techniqueId", "")
            if technique:
                findings.append(self._make_finding(
                    technique, f"SentinelOne: {threat.get('threatName', 'Threat')}",
                    "HIGH", 0.9, record,
                    f"SentinelOne threat: {threat.get('threatName')}"
                ))
        return findings

    def _analyze_defender(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        alert = record.get("alert", {})
        techniques = alert.get("mitreTechniques", [])
        for tech in techniques:
            tid = tech.get("techniqueId", "")
            if tid:
                findings.append(self._make_finding(
                    tid, f"Defender: {alert.get('title', 'Alert')}",
                    "HIGH", 0.85, record,
                    f"Defender alert: {alert.get('description', '')[:200]}"
                ))
        return findings

    def _analyze_elastic(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        rule = record.get("rule", {})
        mitre = rule.get("mitre", {})
        techniques = mitre.get("techniques", [])
        for tech in techniques:
            tid = tech.get("id", "")
            if tid:
                findings.append(self._make_finding(
                    tid, f"Elastic: {rule.get('name', 'Rule')}",
                    "MEDIUM", 0.8, record,
                    f"Elastic rule: {rule.get('description', '')[:200]}"
                ))
        return findings

    def _analyze_generic_edr(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        for pattern in EVENT_PATTERNS:
            if self._matches_pattern(record, pattern):
                findings.append(self._make_finding(
                    pattern["technique_ids"][0], pattern["rule_name"],
                    pattern["severity"], pattern["confidence"], record,
                    pattern["description"]
                ))
        return findings

    def _matches_pattern(self, record: Dict, pattern: Dict) -> bool:
        for cond in pattern.get("conditions", []):
            if cond["type"] == "field_equals":
                if record.get(cond["field"]) != cond["value"]:
                    return False
            elif cond["type"] == "field_contains":
                if cond["value"] not in str(record.get(cond["field"], "")):
                    return False
        return True

    def _make_finding(self, tech_id: str, rule_name: str, severity: str,
                      confidence: float, evidence: Dict, description: str) -> DetectionFinding:
        return DetectionFinding(
            rule_id=f"EDR-{tech_id.replace('.', '-')}",
            rule_name=rule_name,
            severity=severity,
            confidence=confidence,
            source_type="event",
            raw_evidence=evidence,
            mappings=[self._build_mapping(tech_id, confidence)],
            timestamp=str(evidence.get("timestamp", "")),
            host=evidence.get("host", "") or evidence.get("agent", {}).get("hostname", ""),
            description=description,
        )