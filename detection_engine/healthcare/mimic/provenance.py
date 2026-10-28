"""Provenance, license, and checksum constants for MIMIC-IV Clinical Database
Demo v2.2.

All values here are transcribed from the authoritative PhysioNet project page
and its published ``SHA256SUMS.txt``. They are used by the ingestion adapter to
verify that any locally-present dataset files match the official release before
they are parsed.

IMPORTANT
---------
MIMIC-IV Demo is DE-IDENTIFIED CLINICAL data (100 patients, HIPAA Safe Harbor).
It is NOT security audit telemetry and contains NO cyberattack labels. This
adapter uses it only to model *legitimate* clinician/provider -> patient
relationships that provide benign context to the security detectors. The
synthetic security events (benign and attack) are generated separately and are
never represented as originating from PhysioNet or from real patients.
"""

from __future__ import annotations

DATASET_NAME = "MIMIC-IV Clinical Database Demo"
DATASET_VERSION = "2.2"
DATASET_DOI = "10.13026/dp1f-ex47"
DATASET_URL = "https://physionet.org/content/mimic-iv-demo/2.2/"
DATASET_LICENSE = "Open Data Commons Open Database License (ODbL) v1.0"
DATASET_ACCESS = "Open Access (publicly downloadable demo subset)"

CITATION = (
    "Johnson, A., Bulgarelli, L., Pollard, T., Horng, S., Celi, L. A., & Mark, R. "
    "(2023). MIMIC-IV Clinical Database Demo (version 2.2). PhysioNet. "
    "RRID:SCR_007345. https://doi.org/10.13026/dp1f-ex47"
)

# Official download root (ODbL; anyone may access per the PhysioNet access policy).
DOWNLOAD_BASE_URL = "https://physionet.org/files/mimic-iv-demo/2.2"

# Authoritative SHA256 checksums transcribed from
# https://physionet.org/files/mimic-iv-demo/2.2/SHA256SUMS.txt
# Only the tables this adapter consumes are listed; extend as needed.
PUBLISHED_SHA256 = {
    "hosp/patients.csv.gz": "59dcc6cd8450ddf03ad32cc7d76e41caa4c9633541715987f590c74835cf6fae",
    "hosp/admissions.csv.gz": "910b9f160ffdf1e08ea673585393f347c773ccc87d66875c627584a903ae8493",
    "hosp/transfers.csv.gz": "41151539886d12d57159b65ffe4d7df5a7ef8ceb7cd113ea9a56fbfbfd78a87c",
    "hosp/services.csv.gz": "28306d68e952fe2cc9ef6e60b0afda93c27d7a06bee8ef39e71ccc4de5ded793",
    "icu/icustays.csv.gz": "e05e81aa52a3022e522b6832a898101a69b84e64c17bb344d819e458d5bc21b3",
}

# Download command documented for users (no credentials required for the demo).
WGET_COMMAND = (
    "wget -r -N -c -np https://physionet.org/files/mimic-iv-demo/2.2/"
)
