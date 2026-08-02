"""Evaluate repository-owned security scan reports.

Fails the workflow for medium/high Bandit findings or known dependency
vulnerabilities not listed in the checked-in allowlist. The script writes a
Markdown summary so every CI run has readable evidence without GitHub Advanced
Security or SARIF upload permissions.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path) -> object:
    """Load a scanner report with a useful error if report generation failed."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SystemExit(f"Missing required security report: {path}") from error
    except json.JSONDecodeError as error:
        raise SystemExit(f"Invalid JSON security report: {path}: {error}") from error


def dependency_vulnerabilities(report: object) -> list[tuple[str, str]]:
    """Return (package, vulnerability-id) pairs from pip-audit JSON output."""
    if isinstance(report, dict):
        report = report.get("dependencies", [])
    if not isinstance(report, list):
        raise SystemExit("pip-audit report must contain a dependencies list")

    findings: list[tuple[str, str]] = []
    for dependency in report:
        if not isinstance(dependency, dict):
            continue
        package = str(dependency.get("name", "unknown"))
        for vulnerability in dependency.get("vulns", []):
            if isinstance(vulnerability, dict):
                vulnerability_id = str(vulnerability.get("id", "unknown"))
                findings.append((package, vulnerability_id))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bandit", type=Path, required=True)
    parser.add_argument("--pip-audit", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    bandit = load_json(args.bandit)
    audit = load_json(args.pip_audit)
    allowlist = load_json(args.allowlist)
    if not isinstance(bandit, dict):
        raise SystemExit("Bandit report must be a JSON object")
    if not isinstance(allowlist, dict):
        raise SystemExit("Security allowlist must be a JSON object")

    allowed_vulnerabilities = set(allowlist.get("pip_audit_vulnerability_ids", []))
    bandit_findings = [
        finding
        for finding in bandit.get("results", [])
        if finding.get("issue_severity") in {"MEDIUM", "HIGH"}
    ]
    dependency_findings = dependency_vulnerabilities(audit)
    unallowlisted_dependencies = [
        finding
        for finding in dependency_findings
        if finding[1] not in allowed_vulnerabilities
    ]

    lines = [
        "# Repository Security Gate",
        "",
        f"- Medium/high Bandit findings: **{len(bandit_findings)}**",
        f"- pip-audit vulnerability IDs: **{len(dependency_findings)}**",
        f"- Unallowlisted dependency vulnerabilities: **{len(unallowlisted_dependencies)}**",
        "",
    ]
    if bandit_findings:
        lines.extend(["## Bandit findings", ""])
        for finding in bandit_findings:
            lines.append(
                f"- `{finding.get('test_id')}` {finding.get('filename')}:{finding.get('line_number')} — "
                f"{finding.get('issue_text')}"
            )
        lines.append("")
    if unallowlisted_dependencies:
        lines.extend(["## Dependency vulnerabilities", ""])
        for package, vulnerability_id in unallowlisted_dependencies:
            lines.append(f"- `{package}`: `{vulnerability_id}`")
        lines.append("")

    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text("\n".join(lines), encoding="utf-8")

    if bandit_findings or unallowlisted_dependencies:
        raise SystemExit("Repository security gate failed; see security-summary.md")
    print("Repository security gate passed")


if __name__ == "__main__":
    main()
