"""
Edge case tests for revoked technique ID handling.
Tests null guard, remapping, parent/subtechnique construction, and graceful degradation.
"""

import logging
from unittest.mock import patch

import pytest
from attack_v19_core.constants import V19_REVOCATION_MAP
from attack_v19_core.index import ATTACKIndex
from attack_v19_core.loader import ATTACKLoader
from attack_v19_core.models import ATTACKMapping, Domain
from detection_engine.base import BaseDetector


class ConcreteDetector(BaseDetector):
    """Concrete implementation for testing."""

    def detect(self, data):
        return []


class TestRevokedIDHandling:
    """Test revoked technique ID handling in _build_mapping."""

    def setup_method(self):
        self.loader = ATTACKLoader()
        self.index = ATTACKIndex(self.loader)
        self.detector = ConcreteDetector(self.index)

    def test_revoked_id_remapped_with_warning(self, caplog):
        caplog.set_level(logging.WARNING)
        result = self.detector._build_mapping("T1562.001", 0.8)

        assert result is not None
        assert result.technique_id == "T1685"
        assert result.subtechnique_id is None
        assert result.source_technique_id == "T1562.001"
        assert result.resolved_technique_id == "T1685"
        assert result.was_revoked is True
        assert "Auto-remapped to T1685" in caplog.text

    def test_revoked_parent_remapped_to_new_parent(self, caplog):
        caplog.set_level(logging.WARNING)
        result = self.detector._build_mapping("T1562", 0.9)

        assert result is not None
        assert result.technique_id == "T1685"
        assert result.subtechnique_id is None
        assert result.was_revoked is True

    def test_revoked_subtechnique_remapped_to_new_subtechnique(self, caplog):
        caplog.set_level(logging.WARNING)
        result = self.detector._build_mapping("T1562.002", 0.7)

        assert result is not None
        assert result.technique_id == "T1685"
        assert result.subtechnique_id == "T1685.001"
        assert result.resolved_technique_id == "T1685.001"
        assert result.was_revoked is True

    def test_revoked_log_clearing_remapped(self, caplog):
        caplog.set_level(logging.WARNING)

        result1 = self.detector._build_mapping("T1070.001", 0.95)
        assert result1 is not None
        assert result1.technique_id == "T1685"
        assert result1.subtechnique_id == "T1685.005"

        result2 = self.detector._build_mapping("T1070.002", 0.95)
        assert result2 is not None
        assert result2.technique_id == "T1685"
        assert result2.subtechnique_id == "T1685.006"

    def test_unknown_id_returns_none_logs_error(self, caplog):
        caplog.set_level(logging.ERROR)
        result = self.detector._build_mapping("T99999", 0.5)

        assert result is None
        assert "not found in index" in caplog.text
        assert "T99999" in caplog.text

    def test_revoked_id_that_also_missing_returns_none(self, caplog):
        caplog.set_level(logging.ERROR)
        with patch("attack_core.mapping.V19_REVOCATION_MAP", {"T9999": "T8888"}):
            result = self.detector._build_mapping("T9999", 0.5)

        assert result is None
        assert "T8888 not found in index" in caplog.text

    def test_valid_id_returns_mapping(self):
        result = self.detector._build_mapping("T1059", 0.85)

        assert result is not None
        assert isinstance(result, ATTACKMapping)
        assert result.technique_id == "T1059"
        assert result.tactic_id == "TA0002"
        assert result.confidence == 0.85
        assert result.domain == Domain.ENTERPRISE

    def test_subtechnique_returns_subtechnique_fields(self):
        result = self.detector._build_mapping("T1059.001", 0.75)

        assert result is not None
        assert result.technique_id == "T1059"
        assert result.technique_name == "Command and Scripting Interpreter"
        assert result.subtechnique_id == "T1059.001"
        assert result.subtechnique_name == "PowerShell"

    def test_caller_must_filter_none(self):
        technique_ids = ["T1059", "T99999", "T1070.001"]
        mappings = []
        for tid in technique_ids:
            mapping = self.detector._build_mapping(tid, 0.5)
            if mapping is not None:
                mappings.append(mapping)

        assert len(mappings) == 2
        mapped_ids = {m.subtechnique_id or m.technique_id for m in mappings}
        assert "T1059" in mapped_ids
        assert "T1685.005" in mapped_ids

    def test_revocation_map_all_entries_resolvable(self):
        actual_revocations = {k: v for k, v in V19_REVOCATION_MAP.items() if k != v}
        for old_id, new_id in actual_revocations.items():
            tech = self.index.get(new_id)
            assert (
                tech is not None
            ), f"Revoked {old_id} maps to {new_id} but {new_id} not in index"


class TestGracefulDegradation:
    def setup_method(self):
        self.loader = ATTACKLoader()
        self.index = ATTACKIndex(self.loader)

    def test_revoked_ids_resolve_through_revocation_map(self):
        for revoked_id in ["T1562", "T1562.001", "T1070.001", "T1070.002"]:
            assert self.index.get(revoked_id) is not None

    def test_new_v19_ids_resolvable_if_stix_is_v19(self):
        new_ids = [
            "T1682",
            "T1683",
            "T1684",
            "T1685",
            "T1686",
            "T1687",
            "T1688",
            "T1689",
            "T1690",
        ]
        found = [tid for tid in new_ids if self.index.get(tid) is not None]
        assert len(found) >= 5


class TestPreV19Regression:
    def setup_method(self):
        self.loader = ATTACKLoader()
        self.index = ATTACKIndex(self.loader)
        self.detector = ConcreteDetector(self.index)

    @pytest.mark.parametrize(
        "technique_id", ["T1059", "T1565", "T1190", "T1027", "T1036", "T1078", "T1499"]
    )
    def test_unchanged_enterprise_techniques_still_work(self, technique_id):
        result = self.detector._build_mapping(technique_id, 0.8)
        assert result is not None
        assert result.technique_id == technique_id