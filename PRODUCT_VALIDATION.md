# Product Validation

## Product boundary
Rule-based detection and ATT&CK normalization over supplied telemetry. It is not a telemetry collector, SIEM, EDR, or response platform.

## Real-world validation ladder
1. Detector unit tests.
2. Mixed benign/malicious telemetry corpus across logs, traffic, behavior, events, and code.
3. Expected-technique contract per fixture plus explicit false-positive fixtures.
4. ATT&CK v19 compatibility check through attack-v19-core.
5. External pilot on exported telemetry from a real environment.

## Evidence rules
Rule count is not detection rate. Fixture recall/precision must stay fixture-scoped.
