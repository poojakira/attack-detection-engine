# Product Validation

## Product boundary

Attack Detection Engine is a rule-based detection and ATT&CK-mapping engine for telemetry supplied by an upstream collector. It is not an EDR, SIEM, endpoint agent, or automated response platform.

## Real-world validation ladder

1. Unit tests for each detector and ATT&CK mapping.
2. Mixed telemetry contract tests using Sysmon/Windows-event and Zeek/NetFlow-shaped records.
3. Strict ingestion validation: unknown source types, non-object records, non-list source payloads, and oversized batches fail loudly rather than being silently ignored.
4. Replay tests over captured/sanitized telemetry from a consenting lab environment.
5. Differential comparison against an independent detection implementation for selected scenarios.
6. External pilot where findings are reviewed by an analyst before any response action is considered.

## Release gates

- Unknown telemetry source keys must never be silently ignored.
- Batches must be bounded.
- Findings must retain source evidence and ATT&CK mappings.
- Rule count must never be described as a detection-rate or coverage guarantee.
- A missing collector, parser, or rule match must not be represented as a clean system state.
- No automated containment claim is permitted; this repository emits findings only.

## Evidence boundary

Passing these gates proves deterministic behavior for the committed rules and tested telemetry shapes. It does not establish real-world detection efficacy, false-positive rates across arbitrary enterprise environments, or equivalence to a SIEM/EDR product.


## Dependency provenance

The ATT&CK taxonomy/mapping dependency is pinned to immutable commit `087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b` from `poojakira/attack-v19-core`. That revision's CI, Production Gate, Documentation Integrity, and Security Hygiene workflows are green. This prevents a stale or behaviorally different package build from silently changing mapping semantics during installation.

## Pilot corpus: mixed telemetry replay

The committed `tests/fixtures/product_telemetry_corpus.json` and its executable regression test replay representative Windows process events, periodic HTTPS connection records, Python code telemetry, and an empty benign batch through the real detection pipeline. The corpus test uses a deterministic minimal ATT&CK index so detector regressions stay fast and offline; the separate `tests/test_product_contract.py` path retains the pinned full ATT&CK v19 integration check. The corpus requires the expected ATT&CK technique family to be emitted for malicious-shaped cases and zero findings for the empty control.

This corpus is deterministic regression evidence, not a detection-rate benchmark. It does not measure false-positive/false-negative performance on arbitrary enterprise telemetry, and the reserved documentation/test addresses in the fixture are not live threat infrastructure.


## Verification snapshot — 2026-10-03

The pilot corpus passed 5/5 deterministic regression cases covering Windows process telemetry, credential-dumping command telemetry, periodic HTTPS beacon-shaped traffic, Python dynamic-execution telemetry, and an empty benign batch. This is regression evidence, not an enterprise detection-rate benchmark.


## Automotive and embedded-security scope update (October 15, 2026)

The repository also accepts `automotive_can`, `firmware`, and `arm_binary`
offline inputs through `DetectionPipeline`. Verified scope is limited to
synthetic CAN trace parsing and policy findings, selected C/C++ CWE-pattern
candidate findings, and inspection of a locally cross-compiled ARM Cortex-M3
ELF32 sample. A controlled native C fixture produced a reproducible
AddressSanitizer stack-buffer-overflow finding; a separate fixed fixture
rejected the same oversized input. This is an intentionally inserted lab
vulnerability, not a discovery in a production ECU.

For exact sample code, compiler commands, regression tests and unsupported
claims, consult [AUTOMOTIVE_SECURITY.md](AUTOMOTIVE_SECURITY.md). This
update does not retroactively change historical snapshots and does not claim
hardware testing, live vehicle penetration testing, full firmware reverse
engineering, production efficacy, or independent security certification.
The targeted post-merge Windows Python 3.12 run passed 29 tests; a later
Python 3.11 Docker run (October 17, 2026) with two added ARM-ELF regression
tests passed 31 focused tests. Neither number is a full-repository test total.
