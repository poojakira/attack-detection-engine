"""Offline CAN security analysis for authorized laboratory traces.

Input is decoded frame metadata, never transmitted on a vehicle bus.
"""

from collections import defaultdict
from typing import Any

from .base import BaseDetector, DetectionFinding


class AutomotiveCANDetector(BaseDetector):
    def detect(self, records: list[dict[str, Any]]) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        per_id: dict[int, list[tuple[float, bytes]]] = defaultdict(list)
        for record in records:
            arb_id = record.get("arbitration_id")
            extended = record.get("is_extended_id", False)
            if type(arb_id) is not int or type(extended) is not bool:
                raise ValueError(
                    "CAN arbitration_id must be integer and extended flag boolean"
                )
            if not 0 <= arb_id <= (0x1FFFFFFF if extended else 0x7FF):
                raise ValueError("CAN arbitration ID outside configured frame format")
            data = record.get("data", [])
            if not isinstance(data, (list, bytes, bytearray)) or any(
                type(x) is not int or not 0 <= x <= 255 for x in data
            ):
                raise ValueError("CAN data must contain byte values")
            is_fd = record.get("is_fd", False)
            if type(is_fd) is not bool:
                raise ValueError("is_fd must be boolean")
            max_len = 64 if is_fd else 8
            if len(data) > max_len:
                raise ValueError("CAN payload exceeds frame format maximum")
            stamp = record.get("timestamp")
            if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
                raise ValueError("CAN timestamp must be numeric")
            import math

            if not math.isfinite(stamp):
                raise ValueError("CAN timestamp must be finite")
            allowed = record.get("allowed_ids")
            if allowed is not None:
                if not isinstance(allowed, list) or any(
                    type(x) is not int for x in allowed
                ):
                    raise ValueError("allowed_ids must be a list of integers")
                if arb_id not in allowed:
                    findings.append(
                        self._finding(
                            "CAN-ID-001",
                            "Unexpected CAN arbitration ID",
                            "MEDIUM",
                            record,
                        )
                    )
            per_id[arb_id].append((float(stamp), bytes(data)))
        for arb_id, history in per_id.items():
            history.sort(key=lambda pair: pair[0])
            # Flag only explicitly configured, testable rate policies.
            relevant = [r for r in records if r["arbitration_id"] == arb_id]
            limits = [
                r["max_frames_per_second"]
                for r in relevant
                if "max_frames_per_second" in r
            ]
            if not limits:
                continue
            if (
                any(type(x) is not int or x < 1 for x in limits)
                or len(set(limits)) != 1
            ):
                raise ValueError(
                    "max_frames_per_second must be a consistent positive integer per ID"
                )
            threshold = limits[0]
            left = 0
            violation = None
            for right, (stamp, _) in enumerate(history):
                while stamp - history[left][0] >= 1.0:
                    left += 1
                if right - left + 1 > threshold:
                    violation = right - left + 1
                    break
            if violation is not None:
                findings.append(
                    self._finding(
                        "CAN-RATE-001",
                        "CAN message rate policy exceeded",
                        "HIGH",
                        {
                            "arbitration_id": arb_id,
                            "frames_in_window": violation,
                            "threshold": threshold,
                        },
                    )
                )
        return findings

    def _finding(
        self, rule_id: str, name: str, severity: str, evidence: dict
    ) -> DetectionFinding:
        # Automotive lab findings are not assigned unrelated enterprise ATT&CK IDs.
        return DetectionFinding(
            rule_id=rule_id,
            rule_name=name,
            severity=severity,
            confidence=1.0,
            source_type="automotive_can",
            raw_evidence=evidence,
            mappings=[],
            description="Observed policy violation in supplied offline CAN trace",
        )
