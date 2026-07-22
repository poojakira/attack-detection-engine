from typing import List, Any, Dict
from .log_detector import LogDetector
from .traffic_detector import TrafficDetector
from .behavior_detector import BehaviorDetector
from .event_detector import EventDetector
from .code_detector import CodeDetector
from .base import DetectionFinding
from attack_core.index import ATTACKIndex


class DetectionPipeline:
    def __init__(self, index: ATTACKIndex):
        self.log = LogDetector(index)
        self.traffic = TrafficDetector(index)
        self.behavior = BehaviorDetector(index)
        self.event = EventDetector(index)
        self.code = CodeDetector(index)

    def run(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        """
        telemetry keys: logs, traffic, behaviors, events, code
        Returns findings sorted by severity then confidence descending.
        """
        findings = []
        if "logs" in telemetry:
            findings += self.log.detect(telemetry["logs"])
        if "traffic" in telemetry:
            findings += self.traffic.detect(telemetry["traffic"])
        if "behaviors" in telemetry:
            findings += self.behavior.detect(telemetry["behaviors"])
        if "events" in telemetry:
            findings += self.event.detect(telemetry["events"])
        if "code" in telemetry:
            findings += self.code.detect(telemetry["code"])

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda f: (severity_order.get(f.severity, 9), -f.confidence))
        return findings

    def run_and_serialize(self, telemetry: Dict[str, Any]) -> List[Dict]:
        return [self._serialize(f) for f in self.run(telemetry)]

    def _serialize(self, f: DetectionFinding) -> Dict:
        return {
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity,
            "confidence": f.confidence,
            "source_type": f.source_type,
            "host": f.host,
            "timestamp": f.timestamp,
            "description": f.description,
            "attack_mappings": [m.dict() for m in f.mappings],
            "evidence": f.raw_evidence,
        }