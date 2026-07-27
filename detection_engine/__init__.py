"""
attack-detection-engine: Unified ATT&CK-mapped detection engine.
Supports log, network traffic, behavior, EDR events, and static code analysis.
"""

from .base import BaseDetector, DetectionFinding
from .behavior_detector import BehaviorDetector
from .code_detector import CodeDetector
from .event_detector import EventDetector
from .log_detector import LogDetector
from .pattern_library import (
    BEHAVIOR_PATTERNS,
    CODE_PATTERNS,
    EVENT_PATTERNS,
    LOG_PATTERNS,
    TRAFFIC_PATTERNS,
)
from .pipeline import DetectionPipeline
from .rule_engine import RuleEngine, SigmaRule
from .traffic_detector import TrafficDetector

__version__ = "19.1.0"
__all__ = [
    "BaseDetector",
    "DetectionFinding",
    "LogDetector",
    "TrafficDetector",
    "BehaviorDetector",
    "EventDetector",
    "CodeDetector",
    "DetectionPipeline",
    "RuleEngine",
    "SigmaRule",
    "LOG_PATTERNS",
    "TRAFFIC_PATTERNS",
    "BEHAVIOR_PATTERNS",
    "EVENT_PATTERNS",
    "CODE_PATTERNS",
]
