# Repository Provenance Audit

## Decision

**Earliest defensible year for this repository/project lineage: 2026**

**Earliest reachable commit on `main`:** 2026-07-22  
**Commit:** [`51151f34b101`](https://github.com/poojakira/attack-detection-engine/commit/51151f34b10169352ef4206c1913f79fd779dbd8)  
**Commit message:** `feat: Unified ATT&CK-mapped detection engine - log, traffic, behavior, event, code detectors`

## Evidence standard

This audit separates three different things:

1. **Git repository inception** — the earliest reachable commit on the default branch.
2. **Pre-Git source lineage** — accepted only when a dated artifact clearly refers to the same project or an identifiable direct precursor.
3. **Background dates** — course years, publication years, CVE/incident dates, dataset dates, framework versions, test timestamps, and copied changelog labels do **not** backdate a repository unless they directly prove the project's own existence.

Git history is preserved as historical evidence. It is not rewritten or backdated from later documents.

## Findings

- No direct pre-2026 commit, course artifact, or exact-name Drive artifact was found.

## Provenance conclusion

The evidence reviewed supports **2026** as the earliest defensible year for this repository. Earlier dates may exist in referenced research, source datasets, publications, standards, or unrelated/precursor academic work, but no direct evidence reviewed here justifies rewriting this repository's Git history to an earlier year.

## Audit scope

Evidence considered in this pass included:

- reachable Git commit history on `main`;
- repository README, changelog, reports, and documentation;
- date-like labels in high-visibility files;
- course/project references where present;
- connected Drive metadata/search for exact or closely related project names;
- previously verified academic/publication evidence, used only as background unless a direct lineage could be established.

**Audit date:** 2026-09-21


## Expanded proof matrix

| Evidence source | What was checked | Result |
|---|---|---|
| Reachable Git history | Earliest reachable commit on `main` | **2026-07-22** — [`51151f34b101`](https://github.com/poojakira/attack-detection-engine/commit/51151f34b10169352ef4206c1913f79fd779dbd8) — `feat: Unified ATT&CK-mapped detection engine - log, traffic, behavior, event, code detectors` |
| Repository files/docs | README, changelog, reports, embedded date labels, provenance files, and high-visibility docs | No dated file reviewed establishes this repository or a clearly identifiable direct precursor before **2026**. |
| Course/project references | Course codes, academic project references, publication links, and research-period references present in or connected to the repository | No course/publication reference reviewed proves this repository existed before **2026**. Earlier academic work remains a separate provenance track unless direct lineage is documented. |
| Internal evidence | Repository-local evidence files and previously audited connected-source metadata | Supports the documented 2026 development/research period; no direct pre-2026 same-project artifact was established. |
| Commit identity/history integrity | Historical author/committer objects and existing timestamps | Preserved as-is. No commits were backdated, timestamp-rewritten, or replaced to manufacture an older timeline. |

### Repository-specific evidence notes

- No direct pre-2026 commit, course artifact, or exact-name Drive artifact was found.

### Provenance confidence

**High for the mapped year (2026).** The reachable Git history is direct evidence. Any earlier year would require a dated source artifact that can be tied to this exact repository or a clearly identifiable direct precursor.

### History policy

This audit records provenance **without rewriting Git history**. If stronger pre-Git evidence is discovered later, document it as pre-Git lineage with the artifact date and source; do not alter historical commit timestamps.


## Automotive and embedded-security scope update (October 15, 2026)

The repository also accepts `automotive_can`, `firmware`, and `arm_binary`
offline inputs through `DetectionPipeline`. Verified scope is limited to
synthetic CAN trace parsing and policy findings, selected C/C++ CWE-pattern
candidate findings, and inspection of a locally cross-compiled ARM Cortex-M3
ELF32 sample. A controlled native C fixture produced a reproducible
AddressSanitizer stack-buffer-overflow finding; a separate fixed fixture
rejected the same oversized input. This is an intentionally inserted lab
vulnerability, not a discovery in a production ECU.

For exact sample code, compiler commands, regression tests and unsupported
claims, consult [AUTOMOTIVE_SECURITY.md](AUTOMOTIVE_SECURITY.md). This
update does not retroactively change historical snapshots and does not claim
hardware testing, live vehicle penetration testing, full firmware reverse
engineering, production efficacy, or independent security certification.
The targeted post-merge Windows Python 3.12 run passed 29 tests; a later
Python 3.11 Docker run (October 17, 2026) with two added ARM-ELF regression
tests passed 31 focused tests. Neither number is a full-repository test total.


## Healthcare dataset provenance — MIMIC-IV Demo v2.2 (October 27, 2026)

This update is additive and does not alter any snapshot above.

### Dataset attribution

The healthcare detection module's legitimate clinical context is derived from:

> Johnson, A., Bulgarelli, L., Pollard, T., Horng, S., Celi, L. A., & Mark, R.
> (2023). **MIMIC-IV Clinical Database Demo** (version 2.2). PhysioNet.
> RRID:SCR_007345. https://doi.org/10.13026/dp1f-ex47

- **License:** Open Data Commons Open Database License (ODbL) v1.0.
- **Access:** Open Access — the 100-patient demo subset is publicly downloadable
  (no credentialing required for the demo). Source:
  https://physionet.org/content/mimic-iv-demo/2.2/
- **DOI:** 10.13026/dp1f-ex47

### Provenance verification performed

The five tables the adapter consumes (`hosp/patients.csv.gz`,
`hosp/admissions.csv.gz`, `hosp/transfers.csv.gz`, `hosp/services.csv.gz`,
`icu/icustays.csv.gz`) were downloaded from PhysioNet and their SHA256 digests
verified **OK** against the authoritative published `SHA256SUMS.txt`. The
adapter (`detection_engine/healthcare/mimic/adapter.py`) re-verifies these
checksums at load time and refuses to parse a file whose digest does not match
`detection_engine/healthcare/mimic/provenance.py`. Observed load on the real
demo: 100 patients, 275 admissions, 170 providers, 0 skipped rows.

### Critical data-separation statement

MIMIC-IV Demo is **de-identified CLINICAL data** (HIPAA Safe Harbor, no free-text
notes). It contains **no security audit telemetry and no cyberattack labels**.
This project uses it **only** to model documented *provider→patient care
relationships* (from the `admissions` table's `admit_provider_id`) that give
benign context to the detectors. An admission link establishes that a provider
was recorded on a patient's admission; it is **not** proof that the provider is
authorized to access that record, and the adapter stores it as a mitigating
`care_relationships` signal rather than an authorization grant. Simulated access
events are never described as a real clinician accessing actual patient records.

All security events — benign and attack — are produced by a **separate, clearly
labeled synthetic generator** (`detection_engine/healthcare/synthetic.py`,
`data_origin="synthetic"`). Generated events are fictional. They are **not**
real hospital security incidents, **not** derived from MIMIC patients, and are
**never** represented as supplied by PhysioNet. The downloaded dataset files are
git-ignored (`mimic_data/`) and are not committed to this repository.
