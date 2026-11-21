"""Provenance from exact tracked source only; installed wheels report UNKNOWN."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

APP_VERSION = "1.1.0"
RULE_VERSION = "clinical-access-1.1"
CORE_REVISION = "087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b"


def source_provenance():
    root = Path(__file__).resolve().parents[2]
    result = {"commit": "UNKNOWN", "clean": None}
    try:
        # Never inherit an unrelated enclosing Git worktree.
        if not (root / ".git").exists():
            return result

        def git(*args):
            return subprocess.check_output(
                ["git", "-C", str(root), *args],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).strip()

        if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
            return result
        if (
            git(
                "ls-files", "--error-unmatch", "detection_engine/platform/provenance.py"
            )
            != "detection_engine/platform/provenance.py"
        ):
            return result
        result = {
            "commit": git("rev-parse", "HEAD"),
            "clean": not bool(git("status", "--porcelain")),
        }
    except (OSError, subprocess.SubprocessError):
        pass
    return result


def source_hash():
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(
            path.relative_to(root).as_posix().encode()
            + b"\0"
            + path.read_bytes()
            + b"\0"
        )
    return digest.hexdigest()
