"""Pipeline integration tests for the clinical_access healthcare source.

Requires the pinned ATT&CK index (provided by the session-scoped ``attack_index``
fixture in conftest.py; skipped if attack_v19_core is unavailable). Verifies:
  * the new source is accepted and dispatched by DetectionPipeline,
  * the bulk-export rule attaches ATT&CK T1567,
  * healthcare and automotive sources coexist in one run,
  * the strict telemetry contract still rejects unknown sources.
"""

import pytest

from detection_engine.healthcare.context import ClinicalContext
from detection_engine.healthcare.synthetic import SyntheticAccessGenerator

SEED = 1337


@pytest.fixture()
def pipeline_with_context(attack_index):
    from detection_engine.pipeline import DetectionPipeline

    gen = SyntheticAccessGenerator(seed=SEED)
    org = gen.build_org()
    ctx = ClinicalContext.from_synthetic_org(org)
    pipe = DetectionPipeline(attack_index, clinical_context=ctx)
    return gen, org, pipe


class TestClinicalAccessPipeline:
    def test_source_is_accepted(self, pipeline_with_context):
        _, _, pipe = pipeline_with_context
        assert "clinical_access" in pipe.ALLOWED_SOURCES

    def test_benign_rounds_no_high_findings(self, pipeline_with_context):
        gen, org, pipe = pipeline_with_context
        events = [e.model_dump(mode="json") for e in gen.benign_rounds(org)]
        findings = pipe.run({"clinical_access": events})
        assert not [f for f in findings if f.severity in {"HIGH", "CRITICAL"}]

    def test_bulk_export_maps_to_t1567(self, pipeline_with_context):
        gen, org, pipe = pipeline_with_context
        events = [e.model_dump(mode="json") for e in gen.attack_bulk_export(org)]
        findings = pipe.run({"clinical_access": events})
        exfil = next(f for f in findings if f.rule_id == "HC-EXFIL-BULKEXPORT")
        technique_ids = [m.technique_id for m in exfil.mappings]
        assert "T1567" in technique_ids

    def test_healthcare_and_automotive_coexist(self, pipeline_with_context):
        gen, org, pipe = pipeline_with_context
        events = [e.model_dump(mode="json") for e in gen.attack_bulk_access(org, 60)]
        # automotive_can empty list must not interfere; both sources accepted.
        findings = pipe.run({"clinical_access": events, "automotive_can": []})
        assert any(f.source_type == "clinical_access" for f in findings)

    def test_unknown_source_still_rejected(self, pipeline_with_context):
        _, _, pipe = pipeline_with_context
        with pytest.raises(ValueError):
            pipe.run({"not_a_real_source": []})

    def test_serialization_roundtrip(self, pipeline_with_context):
        gen, org, pipe = pipeline_with_context
        events = [e.model_dump(mode="json") for e in gen.attack_bulk_export(org)]
        serialized = pipe.run_and_serialize({"clinical_access": events})
        assert serialized
        rec = serialized[0]
        assert rec["source_type"] == "clinical_access"
        assert "evidence" in rec
        assert "patient_name" not in rec["evidence"]
