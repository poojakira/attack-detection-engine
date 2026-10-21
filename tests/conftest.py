"""Reuse the expensive, immutable ATT&CK STIX index across integration tests."""

import pytest
from attack_v19_core import ATTACKLoader, ATTACKIndex


@pytest.fixture(scope="session")
def attack_index():
    return ATTACKIndex(ATTACKLoader())
