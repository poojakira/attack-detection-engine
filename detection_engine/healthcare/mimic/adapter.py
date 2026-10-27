"""Configurable MIMIC-IV Demo v2.2 ingestion adapter.

Responsibilities:
  * Resolve a local dataset directory (the caller downloads the ODbL demo with
    the documented ``wget`` command; this adapter does not require credentials).
  * Verify each consumed file's SHA256 against the published checksums before
    parsing (provenance gate).
  * Validate the CSV schema (required columns present).
  * Parse ``patients``, ``admissions``, ``services`` and build a
    ``ClinicalContext`` of *legitimate* provider -> patient relationships from
    real admission data, preserving patient-to-admission linkage.
  * Handle missing values, malformed rows, and unexpected columns without
    crashing: bad rows are skipped and counted, extra columns ignored.

The produced context models BENIGN clinical reality. It carries no security
events. Patient subject_ids are pseudonymized to ``pt-<id>`` tokens; provider
ids are used as opaque actor ids. No free-text clinical content is retained.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

from ..context import ActorProfile, ClinicalContext
from . import provenance as prov


class MimicProvenanceError(RuntimeError):
    """Raised when a dataset file is missing or fails checksum verification."""


class MimicSchemaError(RuntimeError):
    """Raised when a dataset file is missing required columns."""


# Required columns per consumed table (unexpected extra columns are ignored).
_REQUIRED_COLUMNS = {
    "hosp/patients.csv.gz": {"subject_id"},
    "hosp/admissions.csv.gz": {"subject_id", "hadm_id", "admit_provider_id"},
    "hosp/services.csv.gz": {"subject_id", "hadm_id", "curr_service"},
}


@dataclass
class MimicLoadReport:
    """What was loaded, for transparent reporting (no PHI)."""

    verified_files: List[str] = field(default_factory=list)
    patient_count: int = 0
    admission_count: int = 0
    provider_count: int = 0
    skipped_rows: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "dataset": f"{prov.DATASET_NAME} v{prov.DATASET_VERSION}",
            "doi": prov.DATASET_DOI,
            "license": prov.DATASET_LICENSE,
            "verified_files": sorted(self.verified_files),
            "patient_count": self.patient_count,
            "admission_count": self.admission_count,
            "provider_count": self.provider_count,
            "skipped_rows": self.skipped_rows,
        }


class MimicDemoAdapter:
    """Loads and verifies the MIMIC-IV Demo v2.2 dataset from a local dir."""

    def __init__(self, data_dir: str | Path, *, verify_checksums: bool = True):
        self.data_dir = Path(data_dir)
        self.verify_checksums = verify_checksums
        self.report = MimicLoadReport()

    # --- Provenance / IO ----------------------------------------------------

    def _resolve(self, rel_path: str) -> Path:
        path = self.data_dir / rel_path
        if not path.is_file():
            raise MimicProvenanceError(
                f"required dataset file not found: {rel_path}. Download the ODbL "
                f"demo first: {prov.WGET_COMMAND}"
            )
        return path

    def _verify(self, rel_path: str, path: Path) -> None:
        if not self.verify_checksums:
            return
        expected = prov.PUBLISHED_SHA256.get(rel_path)
        if expected is None:
            return  # no published checksum tracked for this file
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise MimicProvenanceError(
                f"checksum mismatch for {rel_path}: expected {expected}, got "
                f"{digest}. Refusing to parse unverified data."
            )
        self.report.verified_files.append(rel_path)

    def _read_rows(self, rel_path: str) -> List[Dict[str, str]]:
        path = self._resolve(rel_path)
        self._verify(rel_path, path)
        with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            columns = set(reader.fieldnames or [])
            required = _REQUIRED_COLUMNS.get(rel_path, set())
            missing = required - columns
            if missing:
                raise MimicSchemaError(
                    f"{rel_path} is missing required column(s): {sorted(missing)}"
                )
            rows: List[Dict[str, str]] = []
            skipped = 0
            for row in reader:
                # Skip malformed rows (short/long) rather than crashing.
                if any(k is None for k in row) or None in row.values():
                    skipped += 1
                    continue
                rows.append(row)
            if skipped:
                self.report.skipped_rows[rel_path] = skipped
            return rows

    # --- Context derivation -------------------------------------------------

    @staticmethod
    def _patient_token(subject_id: str) -> str:
        return f"pt-{subject_id}"

    def build_clinical_context(self) -> ClinicalContext:
        """Build a ClinicalContext of legitimate provider -> patient assignments
        from real MIMIC-IV admission relationships.

        Each ``admit_provider_id`` becomes an actor legitimately associated with
        the patients they admitted. This models benign authorization reality
        against which the security detectors can distinguish anomalies.
        """
        patients = self._read_rows("hosp/patients.csv.gz")
        admissions = self._read_rows("hosp/admissions.csv.gz")

        valid_subjects: Set[str] = {
            r["subject_id"] for r in patients if r.get("subject_id")
        }
        self.report.patient_count = len(valid_subjects)

        provider_panels: Dict[str, Set[str]] = {}
        admission_count = 0
        for adm in admissions:
            subject = adm.get("subject_id", "")
            provider = adm.get("admit_provider_id", "").strip()
            if not subject or subject not in valid_subjects:
                continue
            admission_count += 1
            if not provider:
                continue
            provider_panels.setdefault(provider, set()).add(
                self._patient_token(subject)
            )

        self.report.admission_count = admission_count
        self.report.provider_count = len(provider_panels)

        actors: Dict[str, ActorProfile] = {}
        for provider, panel in provider_panels.items():
            actors[provider] = ActorProfile(
                actor_id=provider,
                actor_type="clinician",
                role="admitting_provider",
                department="",
                assigned_patients=panel,
                shift=(0, 24),  # demo data gives no shift info; no shift restriction
            )
        return ClinicalContext(actors=actors)

    def load_report(self) -> Dict[str, object]:
        return self.report.as_dict()


def compute_sha256(data: bytes) -> str:
    """Helper mirroring the adapter's checksum computation (for tests/tools)."""
    return hashlib.sha256(data).hexdigest()


def gzip_csv_bytes(header: List[str], rows: List[List[str]]) -> bytes:
    """Build a gzipped CSV blob (used by tests to synthesize schema fixtures)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return gzip.compress(buf.getvalue().encode("utf-8"))
