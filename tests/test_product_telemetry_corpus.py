import json
from pathlib import Path

import pytest
from attack_v19_core.models import Domain, Tactic, Technique

from detection_engine import DetectionPipeline

CORPUS = Path(__file__).parent / "fixtures" / "product_telemetry_corpus.json"


class _DeterministicAttackIndex:
    """Minimal ATT&CK index for fast detector-regression tests.

    Full pinned ATT&CK v19 integration is covered separately by
    tests/test_product_contract.py.
    """

    def get_exact(self, attack_id: str):
        return Technique(
            stix_id=f"attack-pattern--{attack_id.lower().replace('.', '-')}",
            attack_id=attack_id,
            name=f"Technique {attack_id}",
            description="Deterministic regression fixture",
            tactic_ids=["execution"],
            platforms=["Windows", "Linux", "Network"],
            data_sources=["Process", "Network Traffic"],
            mitigations=[],
            domain=Domain.ENTERPRISE,
        )

    def tactic_for_technique(self, technique):
        return Tactic(
            stix_id="x-mitre-tactic--execution",
            attack_id="TA0002",
            name="Execution",
            description="Deterministic regression fixture",
            domain=Domain.ENTERPRISE,
        )

    def parent_for(self, technique):
        return technique


@pytest.fixture(scope="module")
def pipeline():
    return DetectionPipeline(_DeterministicAttackIndex())


@pytest.mark.parametrize(
    "case",
    json.loads(CORPUS.read_text(encoding="utf-8")),
    ids=lambda c: c["name"],
)
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
