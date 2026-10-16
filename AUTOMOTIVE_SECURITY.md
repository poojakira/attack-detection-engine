# Automotive and Embedded Security Extension

This extension adds offline, owner-authorized lab analysis. No supplied binary is executed and no frames are transmitted to a physical vehicle.

## Input sources
- `automotive_can`: decoded CAN/CAN-FD frame dictionaries containing integer `arbitration_id`, numeric `timestamp`, byte-array `data`, and optional `is_extended_id`, `is_fd`, `allowed_ids`, and `max_frames_per_second`. It checks structural validity and caller-defined ID/rate policies, not replay detection, malicious-intent attribution, or actual bus activity.
- `firmware`: C/C++ `source_code` plus `language`. Heuristic source checks flag potentially unsafe string operations and emit CWE candidate references; manual review is required.
- `arm_binary`: `binary` containing ELF32 ARM data. Reads ELF header architecture and endianness only, not instruction decoding, disassembly, or exploitability.

## Example

```python
findings = pipeline.run_and_serialize({
    "automotive_can": [{"arbitration_id": 0x123, "timestamp": 0.0,
        "data": [1, 2], "allowed_ids": [0x120], "max_frames_per_second": 5}],
    "firmware": [{"language": "c", "file_path": "ecu.c",
        "source_code": "void f(char*a,char*b){strcpy(a,b);}"}]
})
```

Findings retain the original engine serialization contract; no unrelated ATT&CK mappings are invented.

## Validation

```
python -m pytest -q tests/test_automotive_embedded.py tests/test_automotive_pipeline.py
python -m pytest -q
python -m ruff check detection_engine tests
```

## Explicit limitations
This is a prototype offline extension and not a completed embedded firmware audit, ARM disassembler, vehicle penetration-test platform, production detector, or automotive safety certification. Synthetic test results do not establish detection efficacy on real vehicles.

## Planned upgrades
Integrate real SocketCAN trace ingestion, documented CAN log parsers, embedded C/C++ AST analysis, compiled Cortex-M samples, ARM disassembly, structured penetration test lab reports, and benchmarked false-positive/negative rates. Validate all of these before claiming them.
