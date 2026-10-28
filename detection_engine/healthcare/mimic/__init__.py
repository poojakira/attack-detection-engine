"""MIMIC-IV Clinical Database Demo v2.2 ingestion adapter.

De-identified clinical data used ONLY to model legitimate clinical
relationships that give benign context to the security detectors. Never used to
fabricate security incidents. See ``provenance`` for license/citation and
``adapter`` for the verified loader.
"""

from .adapter import (
    MimicDemoAdapter,
    MimicProvenanceError,
    MimicSchemaError,
)

__all__ = [
    "MimicDemoAdapter",
    "MimicProvenanceError",
    "MimicSchemaError",
]
