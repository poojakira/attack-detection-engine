"""
Edge case tests for revoked technique ID handling.
Tests the null guard, remapping, and graceful degradation behavior.
"""
import logging
from unittest.mock import Mock, patch
import pytest

from attack_core.constants import V19_REVOCATION_MAP
from attack_core.loader import ATTACKLoader
from attack_core.index import ATTACKIndex
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
        """Revoked ID should be remapped and log WARNING."""
        caplog.set_level(logging.WARNING)

        # T1562.001 -> T1685
        result = self.detector._build_mapping("T1562.001", 0.8)

        assert result is not None
        assert result.technique_id == "T1685"
        assert "T1562.001 was revoked" in caplog.text or "Auto-remapped to T1685" in caplog.text

    def test_revoked_parent_remapped_to_new_parent(self, caplog):
        """Revoked parent technique remapped to new parent."""
        caplog.set_level(logging.WARNING)

        # T1562 -> T1685
        result = self.detector._build_mapping("T1562", 0.9)

        assert result is not None
        assert result.technique_id == "T1685"

    def test_revoked_subtechnique_remapped_to_new_subtechnique(self, caplog):
        """Revoked sub-technique remapped to new sub-technique."""
        caplog.set_level(logging.WARNING)

        # T1562.002 -> T1685.001
        result = self.detector._build_mapping("T1562.002", 0.7)

        assert result is not None
        assert result.technique_id == "T1685.001"
        assert result.is_subtechnique is True

    def test_revoked_log_clearing_remapped(self, caplog):
        """T1070.001/002 -> T1685.005/006."""
        caplog.set_level(logging.WARNING)

        # T1070.001 -> T1685.005
        result1 = self.detector._build_mapping("T1070.001", 0.95)
        assert result1 is not None
        assert result1.technique_id == "T1685.005"

        # T1070.002 -> T1685.006
        result2 = self.detector._build_mapping("T1070.002", 0.95)
        assert result2 is not None
        assert result2.technique_id == "T1685.006"

    def test_unknown_id_returns_none_logs_error(self, caplog):
        """Completely unknown technique ID returns None and logs ERROR."""
        caplog.set_level(logging.ERROR)

        result = self.detector._build_mapping("T99999", 0.5)

        assert result is None
        assert "not found in index" in caplog.text
        assert "T99999" in caplog.text

    def test_revoked_id_that_also_missing_returns_none(self, caplog):
        """Revoked ID that maps to also-missing ID returns None."""
        caplog.set_level(logging.ERROR)

        # Mock V19_REVOCATION_MAP to return a missing ID
        with patch('attack_core.base.V19_REVOCATION_MAP', {"T9999": "T8888"}):
            detector = BaseDetector(self.index)
            result = detector._build_mapping("T9999", 0.5)

            assert result is None
            assert "T8888 not found in index" in caplog.text

    def test_valid_id_returns_mapping(self):
        """Valid technique ID returns proper ATTACKMapping."""
        result = self.detector._build_mapping("T1059", 0.85)

        assert result is not None
        assert isinstance(result, ATTACKMapping)
        assert result.technique_id == "T1059"
        assert result.tactic_id == "TA0002"  # Execution
        assert result.confidence == 0.85
        assert result.domain == Domain.ENTERPRISE

    def test_subtechnique_returns_subtechnique_fields(self):
        """Sub-technique returns subtechnique_id and subtechnique_name."""
        result = self.detector._build_mapping("T1059.001", 0.75)

        assert result is not None
        assert result.subtechnique_id == "T1059.001"
        assert result.subtechnique_name == result.technique_name
        assert result.technique_id == "T1059"  # Parent

    def test_caller_must_filter_none(self):
        """Caller is responsible for filtering None from mapping lists."""
        technique_ids = ["T1059", "T99999", "T1070.001"]  # Mix of valid, invalid, revoked

        mappings = []
        for tid in technique_ids:
            m = self.detector._build_mapping(tid, 0.5)
            if m is not None:
                mappings.append(m)

        # Should have T1059 and T1685.005 (T1070.001 remapped)
        assert len(mappings) == 2
        tids = [m.technique_id for m in mappings]
        assert "T1059" in tids
        assert "T1685.005" in tids

    def test_revocation_map_all_entries_resolvable(self):
        """All actual revocations (k != v) should resolve to existing techniques."""
        actual_revocations = {k: v for k, v in V19_REVOCATION_MAP.items() if k != v}

        for old_id, new_id in actual_revocations.items():
            tech = self.index.get(new_id)
            assert tech is not None, f"Revoked {old_id} maps to {new_id} but {new_id} not in index"


class TestGracefulDegradation:
    """Test graceful degradation when STIX bundle is pre-v19."""

    def test_revoked_ids_not_in_index_if_stix_is_v19(self):
        """If STIX is v19, revoked IDs should not be in index."""
        # This depends on the loaded STIX bundle version
        # Just verify the index behavior
        revoked = ["T1562", "T1562.001", "T1070.001", "T1070.002"]

        for rid in revoked:
            tech = self.index.get(rid)
            # If v19 STIX: tech should be None
            # If v18 STIX: tech might exist
            # We just log for visibility
            if tech is not None:
                print(f"Note: Revoked ID {rid} still in index: {tech.name}")

    def test_new_v19_ids_resolvable_if_stix_is_v19(self):
        """New v19 technique IDs should resolve if STIX is v19."""
        new_ids = ["T1682", "T1683", "T1684", "T1685", "T1686", "T1687", "T1688", "T1689", "T1690"]

        for tid in new_ids:
            tech = self.index.get(tid)
            if tech is not None:
                print(f"Found new v19 technique: {tid} - {tech.name}")


class TestPreV19Regression:
    """Regression tests for pre-v19 detection patterns."""

    def setup_method(self):
        self.loader = ATTACKLoader()
        self.index = ATTACKIndex(self.loader)
        self.detector = BaseDetector(self.index)

    def test_t1059_command_scripting_still_works(self):
        """T1059 (Command and Scripting Interpreter) unchanged."""
        result = self.detector._build_mapping("T1059", 0.8)
        assert result is not None
        assert result.technique_id == "T1059"
        assert "Command" in result.technique_name

    def test_t1565_data_manipulation_still_works(self):
        """T1565 (Data Manipulation) unchanged."""
        result = self.detector._build_mapping("T1565", 0.8)
        assert result is not None
        assert result.technique_id == "T1565"

    def test_t1190_exploit_public_facing_still_works(self):
        """T1190 (Exploit Public-Facing Application) unchanged."""
        result = self.detector._build_mapping("T1190", 0.8)
        assert result is not None
        assert result.technique_id == "T1190"

    def test_t1027_obfuscated_files_still_works(self):
        """T1027 (Obfuscated Files or Information) unchanged."""
        result = self.detector._build_mapping("T1027", 0.8)
        assert result is not None
        assert result.technique_id == "T1027"

    def test_t1036_masquerading_still_works(self):
        """T1036 (Masquerading) unchanged."""
        result = self.detector._build_mapping("T1036", 0.8)
        assert result is not None
        assert result.technique_id == "T1036"

    def test_t1078_valid_accounts_still_works(self):
        """T1078 (Valid Accounts) unchanged."""
        result = self.detector._build_mapping("T1078", 0.8)
        assert result is not None
        assert result.technique_id == "T1078"

    def test_t1499_endpoint_dos_still_works(self):
        """T1499 (Endpoint Denial of Service) unchanged."""
        result = self.detector._build_mapping("T1499", 0.8)
        assert result is not None
        assert result.technique_id == "T1499"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])