# Aegis HealthSec — Security Investigation Workbench

Investigate bounded FHIR R4 clinical-access audit files with the repository's actual deterministic detector, correlation engine and PostgreSQL persistence. Import synthetic JSON, inspect source and normalized evidence, change a case threshold, rerun the exact dataset, and export a checksummed report. The React UI calls the authenticated API; no detection result is mocked.

**Version 1.1.0 · local candidate · PARTIAL master-contract status.** This is offline batch analysis, not continuous monitoring or proof of malicious access. No provider keys or paid services are needed. Use only synthetic data for this evaluation; source JSON is retained locally and reference extraction does not guarantee anonymization. Final source-scoped results are generated outside the repository and reviewed before publication; this README does not substitute historical metrics for current evidence.

With Python 3.12, Node 22+, Docker and free local ports 8000/55432:

```sh
./scripts/local-workbench.sh
```

Open `http://127.0.0.1:8000`, sign in as `local-analyst` with the password entered at startup, then **Load synthetic sample → Import and investigate**. The 30-event sample triggers the bulk-read rule at threshold 25. Set the threshold to 40 and **Rerun same dataset** to inspect the removed finding and export its reproducible report. Saved investigations survive browser reload and application/database restart. Ctrl-C stops the local services while retaining their dedicated data volume.

[Complete product, user, architecture, API, operations, threat model, testing and limitations guide](docs/WORKBENCH.md) · [Evidence contract](docs/EVIDENCE.md) · [Changelog](CHANGELOG.md) · [Security reporting](SECURITY.md) · [Forensic baseline](docs/internal/REPOSITORY_AUDIT.md)

The intended immutable evidence archive screenshot (publication handled separately) is [desktop browser evidence](https://raw.githubusercontent.com/poojakira/attack-detection-engine/refs/tags/evidence/local-workbench-20261116/release-evidence/browser/desktop.png). Until that archive exists, this URL is not a claim of published verification.

The main branch already includes FHIR parsing, clinical detection/correlation, authenticated investigation APIs, real PostgreSQL migrations and React incident screens. Older documents claiming these exist only on feature branches are historical. CAN/C++/ARM CLI analysis remains separately implemented and tested where applicable; it is not integrated into this browser workflow. Full FHIR validation, real-patient use, production deployment, independent operational approval and exhaustive historical documentation/remote branch governance are not established by this candidate.
