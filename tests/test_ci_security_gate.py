"""Exercise the repository's security report gate with synthetic scanner output."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

GATE = Path(__file__).resolve().parents[1] / ".github/scripts/security_gate.py"


@pytest.mark.parametrize(
    ("bandit", "audit", "expected"),
    [
        ({"results": [], "errors": []}, {"dependencies": []}, 0),
        ({"results": [], "errors": [{"reason": "synthetic scan error"}]}, [], 1),
        ({"results": []}, [], 1),
        ({"results": [], "errors": []}, {}, 1),
        ({"results": [], "errors": []}, {"dependencies": [{"name": "fixture"}]}, 1),
    ],
)
def test_gate_requires_complete_scanner_reports(tmp_path, bandit, audit, expected):
    bandit_path = tmp_path / "bandit.json"
    audit_path = tmp_path / "audit.json"
    allowlist = tmp_path / "allowlist.json"
    summary = tmp_path / "summary.md"
    for path, payload in (
        (bandit_path, bandit),
        (audit_path, audit),
        (allowlist, {"pip_audit_vulnerability_ids": []}),
    ):
        path.write_text(json.dumps(payload), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(GATE),
            "--bandit",
            str(bandit_path),
            "--pip-audit",
            str(audit_path),
            "--allowlist",
            str(allowlist),
            "--summary",
            str(summary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected, result.stdout + result.stderr
