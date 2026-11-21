# Verification report

**LOCAL ONLY.** Tested source: 76aa71afcb1ba4d940952b4e41d04298452795b5. Fixing source at report time: 76aa71afcb1ba4d940952b4e41d04298452795b5. Hosted observations in [audit findings](AUDIT_FINDINGS.md) identify their separate source SHAs.

Docker Python 3.12.16. Focused security-report regression with pytest 9.0.3 and Ruff 0.8.4. Baseline 4 failed, 1 passed. Patched 5 passed. Full dependency preparation uses requirements.lock with platform extras and the original pinned attack-v19-core. Treat unavailable PostgreSQL, browser/restart and production checks as incomplete.

The shell probe reproduced masked collection failures and confirmed the patched exit behavior without lowering thresholds. On the final tested source, the Python 3.12.16 suite with real PostgreSQL 17, the pinned ATT&CK core and checksum-verified v19.2 data passed 339 tests, 0 failed, 0 skipped, with four warnings and 82.51076515402451% coverage. The two bounded NDJSON tests failed on baseline and passed after the fix. Ruff 0.8.4 lint and formatting and the wheel and sdist builds exited 0. The React build passed in Node 24.22.3 and npm 11.19.1. The base-image pip 25.0.1 scan reported advisories. The follow-up audit of 134 indexed pins with pip upgraded to 26.2.2 found no known vulnerabilities. The local project and VCS-pinned ATT&CK core were outside that index scan. Bandit medium/high and pip check passed. The unmodified CLI Dockerfile build stalled at dependency fetch with the environment’s TLS trust error. No finished release image or browser-to-backend rerun is attested. See attack-detection-engine.verified-check.log, attack-frontend.log, attack-dependency-security.log, attack-updated-pip-pins-audit.log and attack-container-build.log.

- exit=0

The local workflow syntax check used actionlint 1.7.7. The Markdown lexical check inspected relative file targets. It does not establish heading fragments, external targets, or example commands. Logs and command wrappers are in the workspace audit directory.

## Local Docker CLI smoke

The unmodified Docker build stopped at the environment's TLS trust error during dependency fetch. A temporary build input mounted the environment's public CA bundle for pip without changing the tracked Dockerfile or disabling TLS verification. An initial retry exhausted workspace storage. After removing the two test-only Node images, the adapted build exited 0.

Image ID sha256:2fafcfd5fb52cede8b9b40a0341357ded37b28e8ee3c5f393396c4cc9ce5b541. Running as the image's nonroot user with networking disabled and the digest-verified ATT&CK v19.2 data, the CLI accepted one benign NDJSON record, returned one envelope with zero findings and exited 0. This verifies the adapted local CLI image only. The image was not published. The Compose product runtime and browser-to-backend path still need a fresh end-to-end run on the final candidate.
