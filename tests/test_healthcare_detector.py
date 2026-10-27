"""Deterministic rule tests for PatientAccessDetector.

Covers positive detections (each attack scenario fires its expected rule),
benign controls (legitimate access and documented emergency access are NOT
treated as malicious), and generator determinism.

These tests do not require the ATT&CK index: the detector attaches an ATT&CK
mapping only for the bulk-export rule, which is covered separately in the
pipeline integration test where the index is available.
"""

import pytest

from detection_engine.healthcare.context import ClinicalContext
from detection_engine.healthcare.detector import PatientAccessDetector
from detection_engine.healthcare.synthetic import SyntheticAccessGenerator

SEED = 1337
HIGH_OR_CRITICAL = {"HIGH", "CRITICAL"}


@pytest.fixture()
def org_and_detector():
    gen = SyntheticAccessGenerator(seed=SEED)
    org = gen.build_org()
    ctx = ClinicalContext.from_synthetic_org(org)
    det = PatientAccessDetector(context=ctx)  # no index -> no ATT&CK mapping needed
    return gen, org, det


def _rule_ids(findings):
    return {f.rule_id for f in findings}


class TestBenignControls:
    def test_legitimate_rounds_produce_no_malicious_finding(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect([e.model_dump(mode="json") for e in gen.benign_rounds(org)])
        # Assigned-patient access during shift must not yield HIGH/CRITICAL.
        assert not [f for f in findings if f.severity in HIGH_OR_CRITICAL]

    def test_documented_emergency_access_is_review_not_malicious(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.benign_emergency_access(org)]
        )
        ids = _rule_ids(findings)
        assert ids == {"HC-ACCESS-BREAKGLASS"}
        bg = next(f for f in findings if f.rule_id == "HC-ACCESS-BREAKGLASS")
        assert bg.severity == "LOW"  # explicitly not malicious

    def test_in_scope_service_account_not_flagged(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.benign_service_account(org)]
        )
        assert "HC-IDENTITY-SVCSCOPE" not in _rule_ids(findings)
        assert not [f for f in findings if f.severity in HIGH_OR_CRITICAL]


class TestPositiveDetections:
    def test_bulk_access_fires(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.attack_bulk_access(org, 60)]
        )
        assert "HC-ACCESS-BULK" in _rule_ids(findings)

    def test_off_shift_unassigned_fires(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.attack_off_shift_unassigned(org)]
        )
        assert "HC-ACCESS-OFFSHIFT" in _rule_ids(findings)

    def test_denied_then_success_fires(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.attack_denied_then_success(org)]
        )
        f = next(f for f in findings if f.rule_id == "HC-ACCESS-DENYSUCCESS")
        assert f.raw_evidence["denial_count"] >= 3

    def test_service_account_scope_violation_fires(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.attack_service_account_scope_violation(org)]
        )
        assert "HC-IDENTITY-SVCSCOPE" in _rule_ids(findings)

    def test_bulk_export_fires_critical(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.attack_bulk_export(org)]
        )
        f = next(f for f in findings if f.rule_id == "HC-EXFIL-BULKEXPORT")
        assert f.severity == "CRITICAL"
        assert f.raw_evidence["record_count"] >= 1000


class TestThresholdsAndNegatives:
    def test_below_bulk_threshold_does_not_fire(self, org_and_detector):
        gen, org, det = org_and_detector
        # 10 distinct patients < default threshold 25
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.attack_bulk_access(org, 10)]
        )
        assert "HC-ACCESS-BULK" not in _rule_ids(findings)

    def test_small_export_does_not_fire_exfil(self, org_and_detector):
        gen, org, det = org_and_detector
        small = gen.attack_bulk_export(org, records=10)
        findings = det.detect([e.model_dump(mode="json") for e in small])
        assert "HC-EXFIL-BULKEXPORT" not in _rule_ids(findings)

    def test_evidence_contains_no_record_content(self, org_and_detector):
        gen, org, det = org_and_detector
        findings = det.detect(
            [e.model_dump(mode="json") for e in gen.attack_bulk_access(org, 60)]
        )
        for f in findings:
            assert "patient_name" not in f.raw_evidence
            assert "contributing_signal" in f.raw_evidence


class TestDeterminism:
    def test_same_seed_same_org(self):
        o1 = SyntheticAccessGenerator(seed=SEED).build_org()
        o2 = SyntheticAccessGenerator(seed=SEED).build_org()
        a1 = {k: sorted(v.assigned_patients) for k, v in o1.actors.items()}
        a2 = {k: sorted(v.assigned_patients) for k, v in o2.actors.items()}
        assert a1 == a2

    def test_same_seed_same_findings(self):
        def run():
            gen = SyntheticAccessGenerator(seed=SEED)
            org = gen.build_org()
            det = PatientAccessDetector(context=ClinicalContext.from_synthetic_org(org))
            evs = [e.model_dump(mode="json") for e in gen.attack_bulk_access(org, 60)]
            return sorted(f.rule_id for f in det.detect(evs))

        assert run() == run()
