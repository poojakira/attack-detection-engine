"""
attack-detection-engine: Unified ATT&CK-mapped detection engine.
Supports log, network traffic, behavior, EDR events, and static code analysis.
"""

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import BaseDetector, DetectionFinding
    from .behavior_detector import BehaviorDetector
    from .code_detector import CodeDetector
    from .event_detector import EventDetector
    from .log_detector import LogDetector
    from .traffic_detector import TrafficDetector
    from .pipeline import DetectionPipeline
    from .rule_engine import RuleEngine, SigmaRule
    from .pattern_library import (
        LOG_PATTERNS,
        TRAFFIC_PATTERNS,
        BEHAVIOR_PATTERNS,
        EVENT_PATTERNS,
        CODE_PATTERNS,
    )

__version__ = "1.1.0"

# Clinical workbench does not require loading optional STIX tooling on import.
_EXPORTS = {
    "BaseDetector": "base",
    "DetectionFinding": "base",
    "LogDetector": "log_detector",
    "TrafficDetector": "traffic_detector",
    "BehaviorDetector": "behavior_detector",
    "EventDetector": "event_detector",
    "CodeDetector": "code_detector",
    "DetectionPipeline": "pipeline",
    "RuleEngine": "rule_engine",
    "SigmaRule": "rule_engine",
    **{
        name: "pattern_library"
        for name in (
            "LOG_PATTERNS",
            "TRAFFIC_PATTERNS",
            "BEHAVIOR_PATTERNS",
            "EVENT_PATTERNS",
            "CODE_PATTERNS",
        )
    },
}


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    value = getattr(import_module(f".{_EXPORTS[name]}", __name__), name)
    globals()[name] = value
    return value


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
