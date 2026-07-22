from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass, field
from attack_core.models import ATTACKMapping


@dataclass
class DetectionFinding:
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    source_type: str
    raw_evidence: Dict[str, Any]
    mappings: List[ATTACKMapping] = field(default_factory=list)
    timestamp: str = ""
    host: str = ""
    description: str = ""


class BaseDetector(ABC):
    def __init__(self, index):
        self.index = index

    @abstractmethod
    def detect(self, data: Any) -> List[DetectionFinding]:
        """
        Accept raw telemetry; return list of DetectionFinding.
        Must be idempotent and stateless per call.
        """
        pass

    def _build_mapping(self, technique_id: str, confidence: float) -> ATTACKMapping:
        tech = self.index.get(technique_id)
        if tech is None:
            raise ValueError(f"Unknown technique: {technique_id}")
        tactic_id = tech.tactic_ids[0] if tech.tactic_ids else "unknown"
        tactic = self.index._tactics.get(tactic_id)
        return ATTACKMapping(
            tactic_id=tactic_id,
            tactic_name=tactic.name if tactic else tactic_id,
            technique_id=tech.attack_id,
            technique_name=tech.name,
            subtechnique_id=tech.attack_id if tech.is_subtechnique else None,
            subtechnique_name=tech.name if tech.is_subtechnique else None,
            domain=tech.domain,
            confidence=confidence,
            data_sources=tech.data_sources,
            platforms=tech.platforms,
            url=tech.url,
        )