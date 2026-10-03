import json
from pathlib import Path

import pytest
from attack_v19_core import ATTACKIndex, ATTACKLoader
from detection_engine import DetectionPipeline

CORPUS = Path(__file__).parent / "fixtures" / "product_telemetry_corpus.json"


@pytest.fixture(scope="module")
def pipeline():
    return DetectionPipeline(ATTACKIndex(ATTACKLoader()))


@pytest.mark.parametrize("case", json.loads(CORPUS.read_text(encoding="utf-8")), ids=lambda c: c["name"])
def test_product_telemetry_corpus(pipeline, case):
    findings = pipeline.run(case["telemetry"])
    if "expected_findings" in case:
        assert len(findings) == case["expected_findings"]
        return

    prefix = case["expected_technique_prefix"]
    mapped = {
        mapping.technique_id
        for finding in findings
        for mapping in finding.mappings
    }
    assert any(technique.startswith(prefix) for technique in mapped), (
        f"{case['name']} did not map to expected ATT&CK prefix {prefix}; got {sorted(mapped)}"
    )
