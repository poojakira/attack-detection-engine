# Clinical-access detection and data boundaries

## Implemented scope

`detection_engine/healthcare/` provides a normalized `ClinicalAccessEvent`, explicit caller-supplied `ClinicalContext`, a labeled synthetic generator, seven deterministic `PatientAccessDetector` rules and an optional checksum-checking MIMIC demo context adapter. The platform, FHIR connector, persistence, correlation and React UI also exist in this repository; they are described in [PLATFORM.md](PLATFORM.md) and [WORKBENCH.md](docs/WORKBENCH.md). Their existence is not real EHR streaming, clinical authorization validation or production approval.

The current workbench accepts only the documented bounded FHIR R4 metadata subset. It requires a seconds component (optional fractional seconds) with explicit timezone and at least one object agent. Missing optional action/outcome stays UNKNOWN. R4 outcomes 4/8/12 indicate failure levels, not explicit authorization denial. Unsupported present codes and malformed/unsupported entries are rejected/countable. The separate normalized schema historically accepts its documented naive-UTC convention; that does not relax the FHIR adapter.

## Privacy and context

The normalized schema forbids extra fields and rejects some obvious email/SSN/bare-long-number identifiers in selected fields. These are heuristics, not a proof that accepted values are pseudonymous, lawful to process or de-identified. Reference-token extraction can retain identifying values. Findings project normalized metadata; **workbench reports also deliberately retain original JSON**, including fields outside that projection. Only synthetic data is permitted in this evaluation. Do not label exports PHI-free, anonymous or compliant.

`ClinicalContext` is supplied context, not independently established authorization ground truth. Synthetic assignments are fictional. A MIMIC admission's provider–patient link is a documented care relationship, kept separate from `assigned_patients`; it is not an authorization grant. Trusted HR/IAM/scheduling provenance and deployment-specific interpretation remain external prerequisites.

## Rule inventory and interpretation

| Rule | Default signal | Boundary |
|---|---|---|
| `HC-ACCESS-BULK` | At least 25 distinct patient READ/SUCCESS records for one actor in a batch | Threshold crossing, not malicious-intent proof |
| `HC-ACCESS-OFFSHIFT` | Unassigned access outside a supplied shift without break-glass | Requires meaningful caller-supplied profile/shift context |
| `HC-ACCESS-UNASSIGNED` | Access outside a supplied assignment panel | Review signal; care relationships can mitigate but do not authorize |
| `HC-ACCESS-BREAKGLASS` | Break-glass metadata | LOW review signal, not a malicious verdict |
| `HC-ACCESS-DENYSUCCESS` | Default three explicit denials on a resource then success | Current R4 mapping does not infer `denied`; its threshold has no effect without those semantics |
| `HC-IDENTITY-SVCSCOPE` | Service-account resource outside a supplied prefix scope | Requires supplied service profile/scope; empty configured scope has different meaning |
| `HC-EXFIL-BULKEXPORT` | Export of at least 1,000 records in one event | Investigation trigger, not proven exfiltration; T1567 mapping only when a mapping builder/index is supplied |

No trained anomaly model, statistical baseline, population precision/recall or hospital efficacy measurement is established. Batch processing is not continuous monitoring or a general cross-batch session detector. The workbench exposes only two bounded thresholds and uses no authoritative assignment context.

## Run a synthetic detector example

With the package/platform prerequisites installed, this invokes the actual clinical detector without downloading a clinical dataset or constructing the optional STIX index:

```python
from detection_engine.healthcare.context import ClinicalContext
from detection_engine.healthcare.detector import PatientAccessDetector
from detection_engine.healthcare.synthetic import SyntheticAccessGenerator

gen = SyntheticAccessGenerator(seed=1337)
org = gen.build_org()
detector = PatientAccessDetector(context=ClinicalContext.from_synthetic_org(org))
benign = detector.detect(list(gen.benign_rounds(org)))
export = detector.detect(list(gen.attack_bulk_export(org)))
print([f.rule_id for f in benign])
print([f.rule_id for f in export])
```

The benign control has no HIGH/CRITICAL signal; the export contains `HC-EXFIL-BULKEXPORT`. Without an optional index, this example does not demonstrate ATT&CK mapping. Use the supported browser sample for import/persistence/rerun/export acceptance.

## Optional MIMIC context adapter

`MimicDemoAdapter` accepts an operator-supplied local dataset directory and defaults to verifying each consumed file against its recorded digest in `healthcare/mimic/provenance.py` before parsing. `build_clinical_context()` actually reads only `hosp/patients.csv.gz` and `hosp/admissions.csv.gz`; provenance constants list five tables, and the private row reader defines a services schema, but that does not mean all five are consumed by this public method. The API exposes `verify_checksums=False`; do not use that bypass to support a verified-provenance claim. A matching digest binds expected bytes, not data-use authorization, clinical accuracy or patient privacy.

For an independently approved local dataset, import `MimicDemoAdapter` from `detection_engine.healthcare.mimic.adapter`, construct it with that dataset root, call `build_clinical_context()` and inspect `load_report()` for consumed/verified files and skipped rows. These dataset-dependent calls were source-reviewed, not executed in this documentation pass. Missing files, checksum mismatches and missing required columns raise explicit provenance/schema errors. The adapter derives care relationships rather than security telemetry or cyberattack labels. Its output is not proof of clinician access or misuse. Dataset licensing/access/privacy decisions require the authoritative publisher's terms and an independently approved context; no download or real-clinical-data processing was performed in this documentation pass. The [historical attribution/provenance record](PROVENANCE.md#healthcare-dataset-provenance--mimic-iv-demo-v22-october-27-2026) retains its original observations; they are not newly executed or independently certified here.

## Verification and remaining gates

Schema/detector/synthetic/pipeline/MIMIC fixture tests exercise named cases. Current full-suite and browser results must identify the actual frozen commit in [EVIDENCE.md](docs/EVIDENCE.md). Historical 116-test/real-demo records remain historical; they are not current results or authorization to process real PHI. Full FHIR conformance, real EHR feeds, authoritative clinical context, representative accuracy, privacy/legal review and operational approval remain NOT IMPLEMENTED or NOT VERIFIED as recorded.
