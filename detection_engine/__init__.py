"""
attack-detection-engine: Unified ATT&CK-mapped detection engine.
Supports log, network traffic, behavior, EDR events, and static code analysis.
"""

from .base import BaseDetector, DetectionFinding
from .log_detector import LogDetector
from .traffic_detector import TrafficDetector
from .behavior_detector import BehaviorDetector
from .event_detector import EventDetector
from .code_detector import CodeDetector
from .pipeline import DetectionPipeline
from .rule_engine import RuleEngine, SigmaRule
from .pattern_library import (
    LOG_PATTERNS, TRAFFIC_PATTERNS, BEHAVIOR_PATTERNS,
    EVENT_PATTERNS, CODE_PATTERNS
)

__version__ = "19.1.0"
__all__ = [
    "BaseDetector", "DetectionFinding",
    "LogDetector", "TrafficDetector", "BehaviorDetector",
    "EventDetector", "CodeDetector",
    "DetectionPipeline", "RuleEngine", "SigmaRule",
    "LOG_PATTERNS", "TRAFFIC_PATTERNS", "BEHAVIOR_PATTERNS",
    "EVENT_PATTERNS", "CODE_PATTERNS",
]