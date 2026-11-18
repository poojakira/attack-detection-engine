# Independent Aegis closure review

**AEGIS-QA-01: VERIFIED CLOSED** at clean source `8ae9090b560871d1e584d717734693bb570fffae`. All 18 bounded independent workflow/provenance observations passed. No new product defect was found within this scope. Overall master-contract release status remains **PARTIAL**; this focused closure does not establish complete documentation/governance or operational signoff. Hosted CI is **NOT VERIFIED** by this review.

The earlier review at `50b8d8260c4c822c2bbcc75605a176d97bca72ec` remains historical in the parent review directory, including its original failing proof, report and manifest. None of its files were overwritten for this closure.

## Source and engineering evidence

Product: `poojakira/attack-detection-engine`, Aegis HealthSec 1.1.0, branch `codex/local-workbench-20261116`, rule `clinical-access-1.1`. The source remained clean before and after these checks. Exact installed core VCS metadata identifies `087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b`.

All **74** artifacts in the refreshed engineering manifest matched their declared SHA-256 and byte size; its SHA-256 is `a427b9706c28c204eb7eb79eff1d29b91d9651f97eaee29c85946e0345829d2f`. Hash-verified JUnit records 327 outcomes, zero failures/errors/skips; coverage line rate is 82.47%. Refreshed engineering browser/wheel evidence reports 9/7 checks. These engineering results were verified as evidence, not rerun as an independent full regression suite. All 47 Python modules in the current wheel byte-match source. Eight application/CSS source contents embedded in the served build's maps match source; lock and build hashes are captured in `provenance.json`.

## New independent observations

The real Chromium/source API/PostgreSQL workflow ran **2026-11-18 04:06:21–04:06:30 UTC**, with 14 successful observations recorded in `runtime-results.json`. It covered:

- Synthetic AuditEvent import: 30 persisted events, canonical bulk-read finding, real correlated incident, source/normalized evidence, explicit uncertainty and actual source provenance.
- Same exact retained input at threshold 25 → 40: one removed finding and unchanged event identities. Unicode title `Synthetic review — Café Ω 東京 🩺` preserved. Download/API bytes equal, 42,472 bytes, SHA-256 **`a1ccc390042d222d970ee8bee10f01ff2f7c4bab9d4f48e76e276d615cacc4f2`** matching the server checksum header.
- A committed-but-delayed rerun superseded by input editing does not resurrect obsolete UI output; reconciliation retains its committed report. A delayed export superseded by a run switch does not download. Historical stale rerun returns 409 with no extra run.
- Missing optional action/outcome remains `unknown` for 30 benign records; three unsupported/non-object entries are counted as rejected; unsupported present action returns 422. No invented bulk finding at threshold 2.
- Controlled same-org auditor read/export allowed and write/rerun forbidden; foreign-org object/export/rerun returns 404 with empty list; unauthenticated access returns 401.
- Actual API restart invalidates old token, preserves all three reports and identical report bytes; fresh Chromium login restores case/history. No page errors.

QA01 was reproduced against the repaired build using the **same failing mechanism**: hold the initial list after fetching actual API response bytes, complete a real import and fresh list, then release the old list. `new_case_visible_after_old_list` is now **true**. The mount and post-run refresh share a monotonic list-request sequence with success/error and unmount guards, independent of editor revision.

Four supplementary checks completed **2026-11-18 04:07:55–04:07:59 UTC** in `supplementary-results.json`:

1. The only initial actual list response remains usable after ordinary title/input edits while pending; editor revision does not discard it.
2. A controlled stale 503 response released after a successful real import/list refresh cannot overwrite the fresh list or show an obsolete error. The synthetic failure is injected browser-side; all data processing is actual API/PostgreSQL.
3. The independently launched installed package resides under the separate wheel venv. Its 47 Python modules match the freshly hashed wheel. Outside source, provenance correctly reports `UNKNOWN`/null; source-content hash is `da72e5cd872fb18abce645970fdf83ef74a9699918ceca8238c0ac9ee5b2faa4`.
4. That wheel applies packaged migrations in a separately created disposable DB, imports the real sample, reruns to the actual finding delta, restarts as a real API process, and preserves both reports and byte-identical Unicode export. Wheel report SHA-256: **`2a1adf468cae07d4bc40885743f7552a1182d5112a14fb1b92d35f2bc6571a15`**.

One supplementary harness attempt exited 1 because it used case-sensitive Python dictionary lookup for the HTTP checksum header. The harness was corrected to compare header names case-insensitively and the supplementary checks reran successfully. This was a reviewer harness error, not a product checksum failure; it is explicitly preserved in `recovered-harness-failure.json`. The first attempt had already created/applied wheel migrations; its synthetic DB was retained and reused for the final wheel run.

## Reproduction and scope

Commands (all final executions exit 0):

```text
python /workspace/work/reviews/attack-detection-engine/closure-8ae9090/verify-baseline.py
/workspace/work/envs/attack/bin/python /workspace/work/reviews/attack-detection-engine/closure-8ae9090/provenance-review.py
/workspace/work/envs/hf/bin/python /workspace/work/reviews/attack-detection-engine/closure-8ae9090/independent-review.py
/workspace/work/envs/hf/bin/python /workspace/work/reviews/attack-detection-engine/closure-8ae9090/supplementary-closure.py
```

The scripts record the exact local-module command and bounded synthetic requests. Source runtime used loopback 18779 and retained `aegis_independent`; wheel used `aegis_independent_closure_wheel` in the same parent-provided disposable PostgreSQL container. No source edits, remote writes, publication, provider keys, real PHI, exploit payloads, child agents, or unrelated services were involved. No tokens/browser storage were logged.

All reviewer-owned API processes are stopped. The parent was notified that the reviewer port is released. PostgreSQL and review DBs were handed back running; the parent subsequently advised it will privately back up/restore the disposable tmpfs databases while performing separate literal-launcher orchestration. This reviewer performed no database/container removal. No more runtime work is pending from this reviewer.

The focused closure establishes the ordinary workflow and the reported consistency fix for this commit. It does not prove field detection accuracy, unauthorized/compromised access, full FHIR conformance, externally anchored audit integrity, exhaustive malicious-input robustness, backup/restore, public deployment readiness, all-document freshness or remote branch/CI governance. Independent full-suite execution and literal-launcher orchestration remain separate evidence responsibilities. No production approval is implied.
