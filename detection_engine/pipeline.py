from typing import Any, Dict, List

from attack_v19_core.index import ATTACKIndex

from .base import DetectionFinding
from .behavior_detector import BehaviorDetector
from .code_detector import CodeDetector
from .event_detector import EventDetector
from .log_detector import LogDetector
from .traffic_detector import TrafficDetector


class DetectionPipeline:
    ALLOWED_SOURCES = {"logs", "traffic", "behaviors", "events", "code"}

    def __init__(self, index: ATTACKIndex, max_records_per_source: int = 10_000):
        if max_records_per_source < 1:
            raise ValueError("max_records_per_source must be positive")
        self.max_records_per_source = max_records_per_source
        self.log = LogDetector(index)
        self.traffic = TrafficDetector(index)
        self.behavior = BehaviorDetector(index)
        self.event = EventDetector(index)
        self.code = CodeDetector(index)

    def _validate_telemetry(self, telemetry: Dict[str, Any]) -> None:
        if not isinstance(telemetry, dict):
            raise TypeError("telemetry must be an object keyed by source type")

        unknown = sorted(set(telemetry) - self.ALLOWED_SOURCES)
        if unknown:
            raise ValueError(f"unsupported telemetry source(s): {', '.join(unknown)}")

        for source, records in telemetry.items():
            if not isinstance(records, list):
                raise TypeError(
                    f"telemetry source {source!r} must contain a list of records"
                )
            if len(records) > self.max_records_per_source:
                raise ValueError(
                    f"telemetry source {source!r} exceeds max_records_per_source="
                    f"{self.max_records_per_source}"
                )
            if any(not isinstance(record, dict) for record in records):
                raise TypeError(
                    f"telemetry source {source!r} contains a non-object record"
                )

    def run(self, telemetry: Dict[str, Any]) -> List[DetectionFinding]:
        """
        telemetry keys: logs, traffic, behaviors, events, code
        Returns findings sorted by severity then confidence descending.
        """
        self._validate_telemetry(telemetry)
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
            "attack_mappings": [m.model_dump() for m in f.mappings],
            "evidence": f.raw_evidence,
        }
