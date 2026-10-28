"""Connector base interface and result types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import SecurityEvent


class ConnectorError(Exception):
    """Raised for a whole-payload failure (e.g. unparseable envelope)."""


@dataclass
class ParsedItem:
    """One source item's outcome: either a normalized event or a rejection."""

    index: int
    event: Optional[SecurityEvent] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.event is not None and self.error is None


@dataclass
class ConnectorResult:
    source_type: str
    connector_version: str
    items: List[ParsedItem] = field(default_factory=list)

    @property
    def events(self) -> List[SecurityEvent]:
        return [i.event for i in self.items if i.ok]

    @property
    def errors(self) -> List[Dict[str, Any]]:
        return [{"index": i.index, "error": i.error} for i in self.items if not i.ok]

    def as_summary(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "connector_version": self.connector_version,
            "parsed": len(self.items),
            "normalized": len(self.events),
            "rejected": len(self.errors),
            "errors": self.errors,
        }


class Connector(ABC):
    """Versioned source-format adapter. Subclasses implement parsing +
    normalization only; they never touch the database."""

    source_type: str = "unknown"
    connector_version: str = "0.0"

    @abstractmethod
    def parse(self, payload: Any, *, organization_id: str, max_items: int) -> ConnectorResult:
        """Validate + normalize a payload into a ConnectorResult. Must not raise
        on individual malformed items (record them as rejections); may raise
        ConnectorError only for a fundamentally unusable envelope."""
        raise NotImplementedError
