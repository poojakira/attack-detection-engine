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
