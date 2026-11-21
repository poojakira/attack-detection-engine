# Current evidence pointer

The architecture/notebook/selected-branch pass uses the generated immutable non-release archive [evidence/selected-branches-20261118](https://github.com/poojakira/attack-detection-engine/tree/evidence/selected-branches-20261118/release-evidence). Its manifest is the source of truth for the actual candidate SHA, clean state, fresh test/browser/security outcomes, local notebook checks, remote limitations and artifact hashes. No fixed prior SHA in this guide attests to a later commit.

Only `main` and `codex/local-workbench-20261116` remain as remote branches at the cleanup's recorded verification time. Read [current branch policy](BRANCHES.md), [detailed architecture](ARCHITECTURE.md), and [browser testing access](TRY_IT.md). The records below retain their original source/date and may describe more branches before this owner-requested reduction. No software release, main merge or public full-app hosting occurred.

---

# Evidence and release status

## Published implementation source

The complete immutable non-release archive at `evidence/local-workbench-20261116-complete` contains proof for **`8ae9090b560871d1e584d717734693bb570fffae`**:

- [Assessment and limitations](https://github.com/poojakira/attack-detection-engine/blob/7ec35a68ab0a111a39e8ed48f2dfbc77581406a3/release-evidence/RELEASE_ASSESSMENT.md)
- [Exact commands, environment, times and artifact hashes](https://github.com/poojakira/attack-detection-engine/blob/7ec35a68ab0a111a39e8ed48f2dfbc77581406a3/release-evidence/manifest.json)
- [Focused independent closure](https://github.com/poojakira/attack-detection-engine/blob/7ec35a68ab0a111a39e8ed48f2dfbc77581406a3/release-evidence/independent-review/ASSESSMENT.md)
- [Branch dispositions and restore commands](https://github.com/poojakira/attack-detection-engine/blob/7ec35a68ab0a111a39e8ed48f2dfbc77581406a3/release-evidence/branch-disposition.json)
- [Hosted limitation record](https://github.com/poojakira/attack-detection-engine/blob/7ec35a68ab0a111a39e8ed48f2dfbc77581406a3/release-evidence/remote-ci/status.json)

At that source: 327 individual tests passed with 0 failures/errors/skips; 82.47% line coverage (2489/3018), preserving the 53% gate. Nine engineering browser checks and seven installed-wheel checks passed. Eighteen focused independent observations closed AEGIS-QA-01 and matched 74 then-frozen engineering artifacts; the reviewer did not independently repeat the complete regression. The coordinating engineer's literal-launcher checks (7 browser and 6 restart/persistence observations) included exact export bytes after actual restart and a post-cleanup 327-test repeat. Installed dependency environments were reused; no clean-download-install claim is made.

Candidate Python/npm audits reported 0 known advisories. Full-severity Bandit retained 6 reviewed LOW findings and a nonzero exit while the medium/high gate passed. Secret heuristics' 51 candidates were reviewed as public hashes/revisions or synthetic fixtures; no live checking or suppression baseline. These findings cannot prove absence of secrets/vulnerabilities. The default-main push notice: 17 alerts (4 high/11 moderate/2 low) was distinct from candidate audits and was not resolved by leaving main unchanged.

The archive's 118 public files were hash-verified. An initial incomplete packaging tag is preserved and explicitly superseded by the complete archive; no immutable tag was rewritten. These counts, screenshots and reviews stay tied to 8ae after a later documentation commit.

## Documentation head and provenance rules

Fresh later-head regression/browser/build/security results are **pending until an actual generated manifest identifies that exact frozen head**. The planned new non-release archive is `evidence/docs-reconciliation-20261118`; a name alone does not prove existence or success. [PR #58](https://github.com/poojakira/attack-detection-engine/pull/58) records actual publication status. The [all-document ledger](DOCUMENTATION_AUDIT.md) separates read/source checks, executed examples, syntax-only checks and unavailable or unsafe prerequisites.

Generate final artifacts outside source. Record repository/branch/SHA/clean state, UTC intervals, tool/OS/dependency versions and locks, exact commands/exits, individual JUnit pass/fail/skip counts and separate native subtests, coverage method, builds, runtime/API/browser evidence, screenshots/export and artifact hashes. A current headline cannot borrow an earlier commit's result. [WORKBENCH.md](WORKBENCH.md#testing-evidence-and-security-autopsy) gives the actual gates and destructive-test prerequisites.

Reports bind UTF-8 input/configuration and Python source-content hashes, versions and source status. Per-run IDs/times/incident IDs vary; semantic signals and input/config hashes can be reproduced. Installed wheels report source UNKNOWN outside their exact tracked source root. A checksummed report is not signed, anonymized or externally tamper-proof.

Never save bearer/sessionStorage tokens, bootstrap/database/provider secrets, browser storage dumps, private backups or real PHI in public evidence. Synthetic fixtures must be labeled. Exports retain original supplied fields; inspect before sharing. Syntax validation is not execution of deployment, clinical-data download, test database destruction or an intentionally vulnerable native fixture.

## Hosted CI boundary

At the published 8ae pass, CI 44234954330 remained queued with no jobs; the new `workbench.yml` dispatch returned 404 because it was not registered on unchanged main. Actions-settings read returned 403. An old queued run 40562530813 returned 409 on cancellation. None is a hosted pass. Earlier October reports claimed Actions-disabled status from their then-observed setting; that is historical, not independently re-established by the later 403/queued observations. No security setting or workflow gate was bypassed to force green results.

## Branch disposition

The completed implementation pass retained 14 remote branches: main, this candidate, ten active dependency PR branches, unique unmerged cross-language work and the merged healthcare branch held for its unresolved queued CI. Re-read provider state before later cleanup; this is a dated disposition, not a live API.

| Deleted merged/unused branch | Verified recovery tag |
|---|---|
| `feat/automotive-firmware-can` | `archive/aegis/feat-automotive-firmware-can-20261118` |
| `feat/milestone-c-platform` | `archive/aegis/feat-milestone-c-platform-20261118` |
| `feat/milestone-d-hardening` | `archive/aegis/feat-milestone-d-hardening-20261118` |
| `feat/milestone-e-connectors` | `archive/aegis/feat-milestone-e-connectors-20261118` |
| `fix/automotive-validation-docs` | `archive/aegis/fix-automotive-validation-docs-20261118` |
| `fix/full-test-index-fixture` | `archive/aegis/fix-full-test-index-fixture-20261118` |

Content/transitive merge chains, PR/protection/CI/release/deploy/reference checks, a verified private Git bundle and annotated recovery tags preceded deletion. The private bundle and database backups are not published. No unique/ambiguous branch was deleted, no default history was rewritten and no main merge/deployment/software release occurred. This documentation pass performs no branch mutation.

## Remaining acceptance gates

Hard parser/detector execution isolation/deadline, coordinated multiprocess quotas, full FHIR conformance, authoritative clinical authorization/privacy, external audit anchoring, clean-machine/image/runtime proof and production recovery/operational approval remain missing or unverified. Local all-document reconciliation does not verify external historical chronology, field efficacy, third-party/legal assertions or every deployment command. Release remains **PARTIAL**; see [PRODUCTION.md](../PRODUCTION.md).
