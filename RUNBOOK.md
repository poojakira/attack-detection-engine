# Runbook

## Engineering Update - 2026-07-27

Repository: attack-detection-engine
Purpose: Private ATT&CK v19 detection engine

## Build

- Install: make install
- Lint: make lint
- Format: make format
- Test: make test
- Package build: make build
- Security scan: make security
- Full local gate: make verify

## Dashboard

Static 3D dashboard: dashboard/index.html. Serve with make dashboard after local static validation.

## Dependencies And Data

CI now checks out ../attack-v19-core equivalent via ATTACK_CORE_TOKEN and downloads pinned STIX data.

## Validation Snapshot

Validated: Ruff passed, pytest passed (27 tests), wheel build passed.

## Operating Limits

- Re-check Linux and GitHub Actions after pushing to main.
- Treat local dashboard scores as evidence indicators, not certifications.
- Do not cite production readiness until clean CI, dependency audit, license status, and runtime smoke tests are current.