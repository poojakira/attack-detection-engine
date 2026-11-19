"""Actual guided fixtures and isolated runner, not a mock backend."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo.adapter import SPEC, run  # noqa: E402


@pytest.mark.parametrize("scenario", [item["id"] for item in SPEC["scenarios"]])
def test_canonical_guided_fixture(scenario):
    value = run(scenario)
    assert value["summary"]
    r = value["engine_report"]
    assert r["current"]["event_count"] == 30 and r["current"]["rejected_count"] == 0
    assert len(r["current"]["findings"]) == (0 if scenario == "threshold40" else 1)
    if scenario == "compare":
        assert r["current"]["input_sha256"] == r["after"]["input_sha256"]
        assert r["finding_count_removed"] == 1 and not r["after"]["findings"]


def test_unknown_fixture_rejected():
    with pytest.raises(ValueError):
        run("arbitrary-user-input")


def test_isolated_runner_uses_own_source(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(ROOT / "demo" / "notebook_runner.py"),
            SPEC["scenarios"][0]["id"],
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    value = json.loads(result.stdout)
    assert value["report"]["mode"] == "GUIDED_SYNTHETIC_ONLY"
    assert (
        value["report"]["source"]["commit"]
        == subprocess.check_output(
            [shutil.which("git"), "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    )
    assert len(value["report_sha256"]) == 64
