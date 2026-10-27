"""Tests for the MIMIC-IV Demo v2.2 ingestion adapter.

These tests use a SMALL, LOCALLY-AUTHORED fixture that imitates the MIMIC-IV
CSV schema. It is NOT real MIMIC data and contains no real patients — it exists
only to exercise parsing, checksum verification, schema validation, and
malformed-row handling offline. Real-dataset provenance (SHA256 against the
published sums) is verified out-of-band and documented in PROVENANCE.md.
"""

from pathlib import Path

import pytest

from detection_engine.healthcare.mimic import (
    MimicDemoAdapter,
    MimicProvenanceError,
    MimicSchemaError,
)
from detection_engine.healthcare.mimic.adapter import compute_sha256, gzip_csv_bytes


def _write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


@pytest.fixture()
def fixture_dir(tmp_path):
    """A fictional MIMIC-schema dataset (3 patients, 4 admissions, 2 providers)."""
    patients = gzip_csv_bytes(
        ["subject_id", "gender", "anchor_age"],
        [["1001", "F", "40"], ["1002", "M", "55"], ["1003", "F", "33"]],
    )
    admissions = gzip_csv_bytes(
        ["subject_id", "hadm_id", "admit_provider_id", "admission_type"],
        [
            ["1001", "900001", "PROV-A", "URGENT"],
            ["1002", "900002", "PROV-A", "ELECTIVE"],
            ["1003", "900003", "PROV-B", "URGENT"],
            ["1001", "900004", "PROV-B", "URGENT"],
        ],
    )
    _write(tmp_path / "hosp/patients.csv.gz", patients)
    _write(tmp_path / "hosp/admissions.csv.gz", admissions)
    return tmp_path, patients, admissions


class TestProvenance:
    def test_missing_file_raises(self, tmp_path):
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=False)
        with pytest.raises(MimicProvenanceError):
            adapter.build_clinical_context()

    def test_checksum_mismatch_raises(self, fixture_dir, monkeypatch):
        tmp_path, patients, _ = fixture_dir
        # Point the published checksum map at a wrong value for patients.
        from detection_engine.healthcare.mimic import provenance as prov

        monkeypatch.setitem(
            prov.PUBLISHED_SHA256, "hosp/patients.csv.gz", "deadbeef" * 8
        )
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=True)
        with pytest.raises(MimicProvenanceError):
            adapter.build_clinical_context()

    def test_checksum_match_allows_load(self, fixture_dir, monkeypatch):
        tmp_path, patients, admissions = fixture_dir
        from detection_engine.healthcare.mimic import provenance as prov

        monkeypatch.setitem(
            prov.PUBLISHED_SHA256, "hosp/patients.csv.gz", compute_sha256(patients)
        )
        monkeypatch.setitem(
            prov.PUBLISHED_SHA256, "hosp/admissions.csv.gz", compute_sha256(admissions)
        )
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=True)
        ctx = adapter.build_clinical_context()
        assert "hosp/patients.csv.gz" in adapter.report.verified_files
        assert ctx.actors  # context built


class TestSchemaAndParsing:
    def test_missing_required_column_raises(self, tmp_path):
        bad = gzip_csv_bytes(["subject_id", "gender"], [["1", "F"]])
        _write(tmp_path / "hosp/patients.csv.gz", bad)
        # admissions missing admit_provider_id
        adm = gzip_csv_bytes(["subject_id", "hadm_id"], [["1", "9"]])
        _write(tmp_path / "hosp/admissions.csv.gz", adm)
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=False)
        with pytest.raises(MimicSchemaError):
            adapter.build_clinical_context()

    def test_context_from_admissions(self, fixture_dir):
        tmp_path, _, _ = fixture_dir
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=False)
        ctx = adapter.build_clinical_context()
        # PROV-A admitted subjects 1001 and 1002
        assert ctx.actors["PROV-A"].assigned_patients == {"pt-1001", "pt-1002"}
        # PROV-B admitted 1003 and 1001
        assert ctx.actors["PROV-B"].assigned_patients == {"pt-1003", "pt-1001"}

    def test_patients_are_pseudonymized(self, fixture_dir):
        tmp_path, _, _ = fixture_dir
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=False)
        ctx = adapter.build_clinical_context()
        for prof in ctx.actors.values():
            for pt in prof.assigned_patients:
                assert pt.startswith("pt-")  # tokenized, not a bare id

    def test_report_counts(self, fixture_dir):
        tmp_path, _, _ = fixture_dir
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=False)
        adapter.build_clinical_context()
        rep = adapter.load_report()
        assert rep["patient_count"] == 3
        assert rep["admission_count"] == 4
        assert rep["provider_count"] == 2
        assert rep["license"].startswith("Open Data Commons")

    def test_unknown_subject_in_admissions_ignored(self, tmp_path):
        patients = gzip_csv_bytes(["subject_id"], [["1001"]])
        # admission references subject 9999 not in patients -> ignored
        adm = gzip_csv_bytes(
            ["subject_id", "hadm_id", "admit_provider_id"],
            [["1001", "900001", "PROV-A"], ["9999", "900002", "PROV-Z"]],
        )
        _write(tmp_path / "hosp/patients.csv.gz", patients)
        _write(tmp_path / "hosp/admissions.csv.gz", adm)
        adapter = MimicDemoAdapter(tmp_path, verify_checksums=False)
        ctx = adapter.build_clinical_context()
        assert "PROV-Z" not in ctx.actors
        assert ctx.actors["PROV-A"].assigned_patients == {"pt-1001"}
