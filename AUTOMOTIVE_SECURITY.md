# Offline automotive and embedded analysis

## Actual supported surfaces

These are separate Python pipeline/CLI-compatible telemetry paths, not browser workbench features. No supplied C/C++/firmware is executed by the analyzers and no frame is transmitted to a physical bus.

| Surface | Actual input/control | Limits and interpretation |
|---|---|---|
| `parse_candump_text` | Timestamped classic CAN/CAN-FD hexadecimal text → decoded frame dictionaries | At most 2,000,000 text characters and 10,000 frames; classic/FD data and ID bounds; parser does not capture a bus |
| `AutomotiveCANDetector` / `automotive_can` | Frame metadata, optional `allowed_ids` and consistent positive `max_frames_per_second` per ID | Checks structure and supplied ID/rate policy; rate uses a rolling one-second window; no replay/intent attribution |
| `FirmwareAuditor` / `firmware` | `source_code` string and `language` c/cpp/c++ | At most 2,000,000 characters; three regex families flag unsafe string copy/input/format candidates; not AST analysis or exploit proof |
| `ARMBinaryAnalyzer` / `arm_binary` | Actual ELF32 ARM bytes | 52–32,000,000 bytes, bounded program-header table; architecture/endianness/entry/hash/segment structures, writable-executable and executable-stack candidates; not instruction decoding or execution |

ARM validation checks loadable segment bounds and entry placement relative to executable ranges. No unrelated enterprise ATT&CK mapping is invented for these findings. A Python bytes input cannot be represented directly as ordinary JSON; the NDJSON CLI does not provide an implicit base64 firmware decoder.

## Run a bounded offline example

The following parses supplied text and inspects the committed synthetic ELF as data. It does not compile or execute the firmware:

```python
from pathlib import Path
from detection_engine.candump_parser import parse_candump_text
from detection_engine.arm_binary_analyzer import ARMBinaryAnalyzer
from detection_engine.firmware_auditor import FirmwareAuditor

frames = parse_candump_text("(0.000000) can0 123#0102\n")
assert frames[0]["data"] == [1, 2]
findings = ARMBinaryAnalyzer().detect([
    {"file_path": "cortexm_lab.elf", "binary": Path("examples/ecu/cortexm_lab.elf").read_bytes()}
])
assert any(f.rule_id == "ARM-ELF-INFO" for f in findings)
source_findings = FirmwareAuditor().detect([
    {"language": "c", "source_code": "void f(char*a,char*b){strcpy(a,b);}"}
])
assert any(f.rule_id == "FW-C-001" for f in source_findings)
```

`examples/can/normal.candump` and `anomalous.candump` are deterministic offline fixtures. Policy limits must be supplied explicitly; an unlabeled trace is not automatically an attack. The [runbook](RUNBOOK.md#offline-cli-and-pipeline) describes pipeline/NDJSON boundaries and pinned ATT&CK prerequisites.

## Verification and historical lab records

The focused tests are `tests/test_automotive_embedded.py`, `test_automotive_evidence.py` and `test_automotive_pipeline.py`. Fresh outcomes belong to the frozen candidate's generated [evidence](docs/EVIDENCE.md), not this static guide. C/C++ compiler, ARM cross-toolchain and AddressSanitizer executions have not been repeated by this documentation pass.

Earlier October records reported cross-compilation of `examples/ecu/cortexm_lab.c` as a Cortex-M3 ELF and an intentionally inserted `strcpy` overflow in the separate `ecu_vulnerable.c` lab fixture, with a corresponding fixed fixture. These are historical owner-recorded controlled-lab observations, not a newly discovered production vulnerability or evidence of a tested ECU. Do not compile/run the intentionally vulnerable native fixture as routine setup. Its source and existing regression artifacts remain available for a separately authorized bounded lab reproduction.

Not established: live vehicle/CAN capture, hardware penetration testing, firmware emulation/disassembly, comprehensive source vulnerability detection, safety certification, commercial deployment or representative false-positive/negative measurements. The prior 29/31/68/70-test snapshots describe their cited historical environments; none attests to a later documentation head.
