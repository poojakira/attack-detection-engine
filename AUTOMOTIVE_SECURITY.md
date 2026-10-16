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

## Reproduced engineering evidence (October 15, 2026)
- `examples/ecu/cortexm_lab.c` was cross-compiled in Ubuntu WSL2 using `arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -Os -ffreestanding -nostdlib -Wl,--gc-sections -T examples/ecu/linker.ld`. The committed `examples/ecu/cortexm_lab.elf` is a real ARM ELF32 binary. `arm-none-eabi-readelf` showed an executable flash segment and a writable RAM segment. Analyzer regression tests use this artifact and intentionally modified segment permissions.
- The isolated `examples/ecu/ecu_vulnerable.c` training fixture was compiled with Clang AddressSanitizer on WSL2. A 16-character synthetic argument produced `AddressSanitizer: stack-buffer-overflow` in `strcpy` (exit 1). `examples/ecu/ecu_fixed.c` rejected the identical input (exit 3). This is a deliberately introduced lab bug, **not** a previously unknown production vulnerability.
- Two reproducible offline timestamped CAN fixtures (`examples/can/normal.candump` and `anomalous.candump`) were parsed using `parse_candump_text`. The synthetic attack trace exercises an unauthorized ID and excessive message frequency. No real CAN bus or vehicle was accessed.
- 29 focused tests passed on Python 3.12.13. Full legacy regression suite is separately tracked. The tools remain **offline lab prototypes** and do not establish deployed automotive intrusion detection, ECU compromise, commercial penetration-testing work, or full firmware reverse engineering.

### Repeat locally
```bash
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -Os -ffreestanding -nostdlib \
  -Wl,--gc-sections -T examples/ecu/linker.ld examples/ecu/cortexm_lab.c -o /tmp/cortexm.elf
arm-none-eabi-readelf -h -l /tmp/cortexm.elf
clang -O1 -g -fsanitize=address -fno-omit-frame-pointer examples/ecu/ecu_vulnerable.c -o /tmp/vulnerable
clang -O1 -g -fsanitize=address -fno-omit-frame-pointer examples/ecu/ecu_fixed.c -o /tmp/fixed
/tmp/vulnerable AAAAAAAAAAAAAAAA  # Expected AddressSanitizer stack-buffer-overflow
/tmp/fixed AAAAAAAAAAAAAAAA       # Expected safe rejection (exit code 3)
```

## Repository-wide test boundary

At the October 15, 2026 checkout, pytest collected 68 tests, and the focused automotive/embedded subset passed 29/29. The full 68-test run remains unverified; the ATT&CK-dependent historical test classes repeatedly load a large STIX index. Do not treat focused results as repository-wide certification. No hardware ECU penetration test, firmware emulation, or production CAN detection-effectiveness benchmark has been performed.
