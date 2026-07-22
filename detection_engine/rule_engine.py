"""
Sigma rule compiler to ATT&CK-mapped detection rules.
"""

import yaml
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from attack_core.models import ATTACKMapping
from attack_core.index import ATTACKIndex


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    severity: str
    technique_ids: List[str]
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    confidence: float = 0.8


class RuleEngine:
    def __init__(self, index: ATTACKIndex):
        self.index = index
        self.rules: List[SigmaRule] = []

    def load_sigma_file(self, file_path: str) -> List[SigmaRule]:
        with open(file_path, 'r') as f:
            content = f.read()

        docs = list(yaml.safe_load_all(content))
        rules = []
        for doc in docs:
            if not doc or doc.get("type") != "rule":
                continue
            rule = SigmaRule(
                rule_id=doc.get("id", ""),
                title=doc.get("title", ""),
                description=doc.get("description", ""),
                severity=doc.get("level", "medium").upper(),
                technique_ids=self._extract_techniques(doc.get("tags", [])),
                logsource=doc.get("logsource", {}),
                detection=doc.get("detection", {}),
                confidence=0.8,
            )
            rules.append(rule)
            self.rules.append(rule)
        return rules

    def _extract_techniques(self, tags: List[str]) -> List[str]:
        techniques = []
        for tag in tags:
            match = re.match(r'attack\.t(\d{4,5})', tag, re.IGNORECASE)
            if match:
                techniques.append(f"T{match.group(1)}")
            match = re.match(r'attack\.t(\d{4})\.(\d{3})', tag, re.IGNORECASE)
            if match:
                techniques.append(f"T{match.group(1)}.{match.group(2)}")
        return techniques

    def compile_rule(self, rule: SigmaRule) -> Dict[str, Any]:
        return {
            "rule_id": rule.rule_id,
            "rule_name": rule.title,
            "severity": rule.severity,
            "technique_ids": rule.technique_ids,
            "conditions": self._compile_detection(rule.detection),
            "confidence": rule.confidence,
        }

    def _compile_detection(self, detection: Dict) -> List[Dict]:
        conditions = []
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field, cond in value.items():
                    conditions.append(self._parse_condition(field, cond))
            elif isinstance(value, list):
                for v in value:
                    conditions.append(self._parse_condition(key, v))
            else:
                conditions.append(self._parse_condition(key, value))
        return conditions

    def _parse_condition(self, field: str, value: Any) -> Dict:
        if isinstance(value, str):
            if value.startswith("|"):
                return {"type": "field_regex", "field": field, "pattern": value[1:]}
            return {"type": "field_equals", "field": field, "value": value}
        elif isinstance(value, dict):
            cond = {"field": field}
            for k, v in value.items():
                if k == "contains":
                    cond["type"] = "field_contains"
                    cond["value"] = v
                elif k == "startswith":
                    cond["type"] = "field_startswith"
                    cond["value"] = v
                elif k == "endswith":
                    cond["type"] = "field_endswith"
                    cond["value"] = v
                elif k == "re":
                    cond["type"] = "field_regex"
                    cond["pattern"] = v
            return cond
        return {"type": "field_equals", "field": field, "value": value}

    def get_all_compiled(self) -> List[Dict]:
        return [self.compile_rule(r) for r in self.rules]