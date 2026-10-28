# Healthcare Clinical-Access Security Detection

This document describes the healthcare detection module added to the engine. It
is written for security engineers evaluating the component. It states what is
implemented and verified, and what is explicitly **not** claimed.

## Scope and status

The module adds a **clinical-access anomaly detection** capability alongside the
existing automotive/ATT&CK detectors. The two domains share one pipeline but are
code-decoupled: healthcare code lives entirely under
`detection_engine/healthcare/` and does not touch the automotive detectors.

| Capability | Status | Evidence |
|---|---|---|
| Normalized clinical-access event schema (PII-rejecting, UTC, correlation-ready) | **VERIFIED** | `detection_engine/healthcare/schema.py`, `tests/test_healthcare_schema.py` |
| FHIR R4 `AuditEvent` normalization (reference tokens only) | **VERIFIED (subset)** | `ClinicalAccessEvent.from_fhir_audit_event`, schema tests |
| Labeled, seed-deterministic synthetic event generator | **VERIFIED** | `synthetic.py`, detector/determinism tests |
| Deterministic `PatientAccessDetector` (7 rules) | **VERIFIED** | `detector.py`, `tests/test_healthcare_detector.py` |
| Pipeline integration as `clinical_access` source | **VERIFIED** | `pipeline.py`, `tests/test_healthcare_pipeline.py` |
| MIMIC-IV Demo v2.2 legitimate-context adapter (checksum-verified) | **VERIFIED** | `mimic/adapter.py`, `tests/test_mimic_adapter.py`, PROVENANCE.md |
| Statistical/behavioral anomaly scoring | **NOT IMPLEMENTED** | deterministic rules only; no trained model, no accuracy metric claimed |
| Real FHIR/EHR live ingestion | **NOT IMPLEMENTED** | schema is FHIR-forward; no live connector exists |
| Persistence, API, dashboard, correlation engine | **NOT IMPLEMENTED** | out of scope for this increment |
| HIPAA compliance | **NOT CLAIMED** | the module can support monitoring/evidence; it is not a compliance attestation |

## The event schema

`ClinicalAccessEvent` is the canonical, source-agnostic record of one
clinical-resource access *as seen by a security monitor*. It is metadata only —
who did what to which resource, when, from where, with what outcome — and
deliberately excludes patient record content.

Privacy properties (enforced, with tests):
- `actor_id`, `patient_ref`, `resource_id`, `session_id` must be **pseudonymous**.
  The schema rejects values that look like plaintext PII (emails, SSNs, bare
  9+ digit MRN/phone-style tokens).
- Unknown/extra fields are **forbidden** (`extra="forbid"`), preventing accidental
  smuggling of fields like `patient_name`.
- Timestamps are normalized to **UTC**.
- `redacted_evidence()` produces the only evidence attached to findings: metadata
  and pseudonymous identifiers, never record content.

## Detection rules

All rules are deterministic and explainable. Each finding records the exact
`contributing_signal` and the metadata that triggered it.

| Rule ID | Severity | Fires when |
|---|---|---|
| `HC-ACCESS-BULK` | HIGH | One actor reads ≥ `bulk_access_threshold` (default 25) distinct patients in the batch |
| `HC-ACCESS-OFFSHIFT` | HIGH | Access to an unassigned patient outside the actor's shift, no break-glass |
| `HC-ACCESS-UNASSIGNED` | MEDIUM | On-shift access to a patient outside the actor's panel (review; may be legitimate cross-coverage) |
| `HC-ACCESS-BREAKGLASS` | LOW | Break-glass/emergency access used — surfaced for **review, not treated as malicious** |
| `HC-ACCESS-DENYSUCCESS` | HIGH | ≥ `denial_streak_threshold` (default 3) denials on one resource then a success (possible authorization probing) |
| `HC-IDENTITY-SVCSCOPE` | HIGH | A service account touches a resource outside its authorized prefix scope |
| `HC-EXFIL-BULKEXPORT` | CRITICAL | A single export event of ≥ `bulk_export_record_threshold` (default 1000) records |

### Design choices that matter

- **A clinician accessing several assigned patients is not an alert.** Legitimate
  rounds (assigned patients, during shift) produce **zero** findings. This is a
  tested benign control.
- **Documented emergency access is a review event, not a malicious verdict.**
  Break-glass yields only a LOW `HC-ACCESS-BREAKGLASS`.
- **ATT&CK is attached only where justified.** Only `HC-EXFIL-BULKEXPORT` maps to
  an ATT&CK technique (**T1567 — Exfiltration Over Web Service**), because it is
  exfiltration-shaped. Access-pattern anomalies emit **no** ATT&CK mapping rather
  than inventing one.
- **A large export is not proof of exfiltration.** The CRITICAL finding is an
  investigation trigger, and its description says so.

## Authorization context

The detector consumes a `ClinicalContext` (`context.py`): per-actor assignment
panels, service-account resource scopes, and shift windows. This is the
authorization ground truth. It can come from:

- the synthetic generator (`ClinicalContext.from_synthetic_org`), or
- the MIMIC-IV Demo adapter (`MimicDemoAdapter.build_clinical_context`), which
  records documented `provider → patient` **care relationships** from real
  admission data (populating `care_relationships`, a mitigating contextual
  signal — **not** `assigned_patients`, because an admission link is not proof
  of access authorization), or
- (future) an authoritative HR/IAM/scheduling feed.

## End-to-end: run it yourself

Prerequisites: the engine installed with the pinned `attack-v19-core` (see
`BASELINE_REPAIR_2026-10-27.md` for the exact isolated-venv steps).

### A. Fully synthetic (no dataset needed)

```python
from attack_v19_core import ATTACKLoader, ATTACKIndex
from detection_engine.pipeline import DetectionPipeline
from detection_engine.healthcare.synthetic import SyntheticAccessGenerator
from detection_engine.healthcare.context import ClinicalContext

gen = SyntheticAccessGenerator(seed=1337)
org = gen.build_org()
ctx = ClinicalContext.from_synthetic_org(org)
pipe = DetectionPipeline(ATTACKIndex(ATTACKLoader()), clinical_context=ctx)

benign = [e.model_dump(mode="json") for e in gen.benign_rounds(org)]
attack = [e.model_dump(mode="json") for e in gen.attack_bulk_export(org)]

print("benign findings:", [f.rule_id for f in pipe.run({"clinical_access": benign})])
print("attack findings:", [f.rule_id for f in pipe.run({"clinical_access": attack})])
```

Expected: benign produces no HIGH/CRITICAL finding; the export produces
`HC-EXFIL-BULKEXPORT` mapped to T1567.

### B. Real legitimate context from MIMIC-IV Demo + simulated attack

First download the ODbL demo (no credentials needed for the demo subset):

```bash
wget -r -N -c -np https://physionet.org/files/mimic-iv-demo/2.2/
# place hosp/ and icu/ under ./mimic_data/
```

```python
from detection_engine.healthcare.mimic import MimicDemoAdapter

adapter = MimicDemoAdapter("mimic_data")        # verifies SHA256 before parsing
ctx = adapter.build_clinical_context()           # documented care relationships
print(adapter.load_report())                      # PHI-free provenance report
```

Then build the pipeline with `clinical_context=ctx` and run **synthetic** access
events as in example A. Because an admission link is modelled as a care
relationship (not an authorization grant), a provider reading a care-related
patient yields a LOW review signal that records the relationship; the same
provider bulk-reading many unrelated patients fires `HC-ACCESS-BULK`. Note: the
access events here are simulated — this is **not** a real clinician accessing
real records.

## Verified test evidence (2026-10-27)

Isolated venv, pinned `attack-v19-core` `087accffc7`, Python 3.12.3:

- Full suite: **116 passed** (70 pre-existing + 46 healthcare: 37 schema/detector/
  pipeline + 9 MIMIC adapter).
- `ruff 0.8.4` check: **All checks passed**.
- Real MIMIC-IV Demo load: 100 patients / 275 admissions / 170 providers,
  all five consumed files SHA256-verified against the published sums.

These figures are deterministic regression/behavior evidence on constructed test
data. They are **not** a detection-rate measurement for any real hospital, and
nothing here constitutes HIPAA certification or production validation.

## Known limitations

- Rules are threshold/deterministic; thresholds are defaults and must be tuned
  per environment. No statistical baseline or ML scoring is implemented.
- Detection runs per batch; there is no persistent cross-batch correlation,
  alert suppression, or stateful session tracking yet.
- The FHIR adapter maps a subset of `AuditEvent` and trusts the caller to supply
  pseudonymous references.
- No live telemetry connectors, storage, API, or dashboard are included in this
  increment.
