from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from typing import Any, TextIO

from attack_v19_core import ATTACKIndex, ATTACKLoader

from .pipeline import DetectionPipeline

_MAX_RECORD_BYTES = 1_048_576


def build_pipeline() -> DetectionPipeline:
    """Build the detector against the pinned ATT&CK data package."""
    loader = ATTACKLoader()
    return DetectionPipeline(ATTACKIndex(loader))


def _iter_records(stream: TextIO) -> Iterable[tuple[int, dict[str, Any]]]:
    """Yield validated NDJSON telemetry records from a text stream."""
    for line_number, raw in enumerate(stream, start=1):
        if not raw.strip():
            continue
        if len(raw.encode("utf-8")) > _MAX_RECORD_BYTES:
            raise ValueError(
                f"line {line_number}: record exceeds {_MAX_RECORD_BYTES} bytes"
            )
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(value, dict):
            raise ValueError(
                f"line {line_number}: telemetry record must be a JSON object"
            )
        yield line_number, value


def _open_input(path: str) -> TextIO:
    return sys.stdin if path == "-" else open(path, encoding="utf-8")


def _open_output(path: str) -> TextIO:
    return sys.stdout if path == "-" else open(path, "w", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read telemetry as NDJSON and emit ATT&CK-mapped detection findings."
    )
    parser.add_argument("--input", default="-", help="NDJSON input path or - for stdin")
    parser.add_argument(
        "--output", default="-", help="NDJSON output path or - for stdout"
    )
    parser.add_argument(
        "--fail-on",
        choices=("never", "critical", "high", "medium", "low", "info"),
        default="never",
        help="Exit 1 when a finding at or above this severity is emitted.",
    )
    args = parser.parse_args(argv)

    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    threshold = 99 if args.fail_on == "never" else severity_rank[args.fail_on.upper()]
    max_seen = 0

    try:
        pipeline = build_pipeline()
        source = _open_input(args.input)
        destination = _open_output(args.output)
        close_source = source is not sys.stdin
        close_destination = destination is not sys.stdout
        try:
            for line_number, telemetry in _iter_records(source):
                findings = pipeline.run_and_serialize(telemetry)
                for finding in findings:
                    max_seen = max(
                        max_seen, severity_rank.get(str(finding["severity"]).upper(), 0)
                    )
                destination.write(
                    json.dumps(
                        {
                            "line": line_number,
                            "finding_count": len(findings),
                            "findings": findings,
                        },
                        sort_keys=True,
                        default=str,
                    )
                    + "\n"
                )
                destination.flush()
        finally:
            if close_source:
                source.close()
            if close_destination:
                destination.close()
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    return 1 if max_seen >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
