from __future__ import annotations

import io
import json

from detection_engine import cli


class _Pipeline:
    def run_and_serialize(self, telemetry):
        assert telemetry["logs"][0]["message"] == "test"
        return [
            {
                "rule_id": "TEST-1",
                "rule_name": "test",
                "severity": "HIGH",
                "confidence": 1.0,
                "source_type": "log",
                "host": "h",
                "timestamp": "t",
                "description": "d",
                "attack_mappings": [],
                "evidence": {},
            }
        ]


def test_cli_processes_ndjson(monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_pipeline", lambda: _Pipeline())
    monkeypatch.setattr(
        cli.sys,
        "stdin",
        io.StringIO(json.dumps({"logs": [{"message": "test"}]}) + "\n"),
    )

    rc = cli.main(["--input", "-", "--output", "-", "--fail-on", "high"])

    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["finding_count"] == 1


def test_cli_rejects_non_object_ndjson(monkeypatch, capsys):
    monkeypatch.setattr(cli, "build_pipeline", lambda: _Pipeline())
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("[]\n"))

    rc = cli.main(["--input", "-", "--output", "-"])

    assert rc == 2
    assert "must be a JSON object" in capsys.readouterr().err
