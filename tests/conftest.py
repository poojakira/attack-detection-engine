"""Reuse the expensive, immutable ATT&CK STIX index across integration tests.

The ``attack_v19_core`` import is performed lazily inside the fixture so that
tests which do not require the ATT&CK index (e.g. the offline automotive /
firmware / ARM-ELF tests) can still be collected and run in environments where
``attack_v19_core`` is not installed. Tests that request ``attack_index`` are
skipped with a clear message when the package is unavailable.
"""

import pytest


@pytest.fixture(scope="session")
def attack_index():
    try:
        from attack_v19_core import ATTACKLoader, ATTACKIndex
    except ImportError:
        pytest.skip("attack_v19_core is not installed")
    return ATTACKIndex(ATTACKLoader())
