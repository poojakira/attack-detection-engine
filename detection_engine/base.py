from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from attack_v19_core.mapping import ATTACKMappingBuilder
from attack_v19_core.models import ATTACKMapping


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
        self.mapping_builder = ATTACKMappingBuilder(index)

    @abstractmethod
    def detect(self, data: Any) -> List[DetectionFinding]:
        """
        Accept raw telemetry; return list of DetectionFinding.
        Must be idempotent and stateless per call.
        """
        pass

    def _build_mapping(
        self, technique_id: str, confidence: float
    ) -> Optional[ATTACKMapping]:
        return self.mapping_builder.build(technique_id, confidence)