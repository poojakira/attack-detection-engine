# Audit findings

## Repository state

Default branch main is b631f31df52e9a7477cbc65dff9b4f46758f71a7. Review started at d3d745f14ed8211b96f4da0a0c6d90947878d291. The collected inventory contains 57 pull requests, 1 issues and 22 Git tags. The public Releases API returned zero release records.

### Open pull requests

- [#58 Add persisted local investigation workbench and source-scoped verification](https://github.com/poojakira/attack-detection-engine/pull/58)

Draft #58 was open and mergeable at the observed base and head. Audit assessment is **BLOCKED**.

### Open issues

- [#37 Investigate Dependabot GitHub Actions updater: No files changed for three action updates](https://github.com/poojakira/attack-detection-engine/issues/37)

Issue #37 concerns the Dependabot updater. The October run executed its updater and logged “No files changed!” for upload-artifact, login-action and setup-buildx-action. The later November run completed and recognized PRs #43, #44 and #57 for those updates, without the prior error. Those PRs closed without merging. The current pins and github-actions ecosystem remain active. Fresh update creation after the closures and the upstream cause remain unverified. Leave #37 open. [Failed run](https://github.com/poojakira/attack-detection-engine/actions/runs/38463079059) · [Successful run](https://github.com/poojakira/attack-detection-engine/actions/runs/43909216838)

### Hosted runs in collected history

- Success on b631f31df52e9a7477cbc65dff9b4f46758f71a7, 2026-11-16T16:36:20Z. [github_actions in /. - Update #1709420126](https://github.com/poojakira/attack-detection-engine/actions/runs/43909216838)
- Failure on 1e11a4156d02a874a228f1e2e95a735b485eb15d, 2026-10-19T16:37:56Z. [github_actions in /. - Update #1637478071](https://github.com/poojakira/attack-detection-engine/actions/runs/39286746302)
- Cancelled on cfdb5c9ef7bb5ffd347a627fb6dba0e7b13c0ac1, 2026-10-28T02:40:40Z. [Addressing comment on PR #47](https://github.com/poojakira/attack-detection-engine/actions/runs/40622056388)

The most recent recorded October failure executed Dependabot and reported its upstream updater error. Category G. The queued manual CI jobs have no job results and no confirmed scheduler diagnosis. The Actions permissions endpoint returned 403 to the public client.

## Confirmed defects

| ID | Severity | Affected file and lines | Root cause, impact and remediation | Status |
|---|---|---|---|---|
| ADE-01 | Medium | .github/workflows/ci.yml:75–84 | Main pip install piped its output to tail in a non-pipefail shell. PR #58 removed the pipe. Explicit Bash adds pipefail to run steps. | Implemented locally |
| ADE-02 | Medium | .github/workflows/ci.yml:86–99 | The old collection pipeline could mask failure and the draft had dropped its minimum. The patch checks pytest status and preserves the five-test minimum. | Implemented locally |
| ADE-03 | High | .github/scripts/security_gate.py:26–84 | An incomplete Bandit or pip-audit report could be interpreted as clean. The patch rejects scan errors and malformed or missing report fields, checks pip-audit status consistency, and preserves dependency allowlist handling. | Implemented locally |
| ADE-06 | Low | README.md and docs/BRANCHES.md | Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record. | Implemented locally |
| ADE-04 | Medium | .github/workflows/workbench.yml:45–49 | The workflow set ATTACK_DATA_DIR for the loader, but the pinned downloader CLI installed into its independent home-directory default. The workflow now passes the same directory explicitly. | Implemented locally |
| ADE-05 | Medium | tests/conftest.py:45–48 | An unavailable database could include the connection URI in pytest skip output. The generic skip reason now avoids rendering that URI. | Implemented locally |
| ADE-07 | Medium | detection_engine/cli.py:20–34 | The line-size check ran after unrestricted stream iteration had already allocated a full line. The CLI now bounds reads before validating UTF-8 byte size, including blank records. Both oversized-line regressions failed on the baseline and passed after the fix. | Implemented locally |

## Residual risk

Main has the earlier FHIR, authentication, persistence and React platform. The draft adds saved case/rerun and evidence export. Three manual CI runs remain queued with zero jobs. The exact scheduler cause is unconfirmed. Full FHIR conformance, hard parser/detector deadlines, multiprocess quotas, clinical data protection and production recovery are unverified.

The review includes the named PRs, selected source, local workflow syntax, relative file targets in Markdown, and the executed checks in [verification](VERIFICATION_REPORT.md). Complete source review, historical per-run root cause classification and validation of all operational documentation remain incomplete.
