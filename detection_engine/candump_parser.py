"""Strict, bounded parser for standard candump text captures.

Supports timestamped classic CAN and CAN FD hexadecimal lines. No capture or
bus interface access is performed.
"""

import re

_CANDUMP = re.compile(
    r"^\((\d+(?:\.\d+)?)\)\s+([A-Za-z][\w.-]{0,31})\s+"
    r"([0-9A-Fa-f]{3}|[0-9A-Fa-f]{8})(#(?:#[0-9A-Fa-f]|)[0-9A-Fa-f]*)$"
)


def parse_candump_text(text: str) -> list[dict]:
    if not isinstance(text, str) or len(text) > 2_000_000:
        raise ValueError("CAN capture must be text of at most 2MB")
    frames: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(frames) >= 10_000:
            raise ValueError("CAN trace exceeds 10,000 frames")
        match = _CANDUMP.fullmatch(line.strip())
        if not match:
            raise ValueError(f"invalid candump frame at line {line_no}")
        timestamp, iface, can_id, payload = match.groups()
        fd = payload.startswith("##")
        if fd:
            if len(payload) < 3:
                raise ValueError(f"CAN FD flags missing at line {line_no}")
            flags = int(payload[2], 16)
            data_text = payload[3:]
        else:
            flags = None
            data_text = payload[1:]
        if len(data_text) % 2:
            raise ValueError(f"CAN payload must be full bytes at line {line_no}")
        data = bytes.fromhex(data_text)
        if len(data) > (64 if fd else 8):
            raise ValueError(f"CAN payload exceeds protocol maximum at line {line_no}")
        arbitration_id = int(can_id, 16)
        extended = len(can_id) == 8
        if arbitration_id > (0x1FFFFFFF if extended else 0x7FF):
            raise ValueError(f"CAN arbitration ID out of range at line {line_no}")
        frames.append(
            {
                "timestamp": float(timestamp),
                "interface": iface,
                "arbitration_id": arbitration_id,
                "is_extended_id": extended,
                "is_fd": fd,
                "fd_flags": flags,
                "data": list(data),
            }
        )
    return frames
