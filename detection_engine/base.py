from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from attack_core.models import ATTACKMapping
from attack_core.constants import V19_REVOCATION_MAP
import logging

logger = logging.getLogger(__name__)


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

    def _build_mapping(self, technique_id: str, confidence: float) -> Optional[ATTACKMapping]:
        # Step 1: Check revocation map first
        resolved_id = V19_REVOCATION_MAP.get(technique_id, technique_id)
        if resolved_id != technique_id:
            logger.warning(
                f"[ATT&CK v19] Technique {technique_id} was revoked. "
                f"Auto-remapped to {resolved_id}. Update rule table."
            )

        # Step 2: Look up resolved ID
        tech = self.index.get(resolved_id)
        if tech is None:
            logger.error(
                f"[ATT&CK v19] Technique {resolved_id} not found in index. "
                f"Original ID: {technique_id}. Skipping mapping."
            )
            return None  # caller must filter None values out of mappings list

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