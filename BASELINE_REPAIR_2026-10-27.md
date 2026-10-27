# Baseline Repair — Dependency Drift Root Cause & Fix (2026-10-27)

Branch: `feat/healthsec-detection` (forked from `feat/arm-elf-hardening-and-ci`).
This record is additive. It does not alter prior dated snapshots.

## Summary

The repository's committed test suite failed **13 of 70** collected tests on
this machine before any source change. Root cause was a **dependency build
mismatch** between the pinned `attack-v19-core` commit the engine is written
against and a *different, API-incompatible* `attack-v19-core` build that was
already installed system-wide. Installing the correct pinned commit into an
isolated virtual environment resolves **all 13 failures with zero changes to
test assertions or source logic**.

No test was deleted, skipped, or weakened. Revoked-ATT&CK-ID regression
coverage (`tests/test_revoked_id_handling.py`) is fully retained and now passes.

## Decision 2 compliance

1. **Reproduce the pin first.** The pinned commit
   `087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b` was fetched from
   `github.com/poojakira/attack-v19-core` and checked out into an isolated
   worktree. It builds and installs cleanly.
2. **The pin passes the original contract tests.** With the pinned commit
   installed, the full suite is green (70/70). Therefore the pin is
   **preserved**; no upgrade is performed.
3. **The locally installed version was NOT used** just because it was present.
   It was identified as the source of the drift and bypassed via an isolated
   venv.

## Root cause detail

| Item | Pinned commit `087accffc7` (correct) | System-installed build `ac78948e` (drifted) |
|---|---|---|
| Self-reported version | `19.2.0` | `19.2.0` |
| `ATTACKMapping.tactic_id` for `T1059` | `"TA0002"` | `"execution"` (tactic *name*, not ID) |
| `ATTACKIndex.get()` | present | **absent** (tests call `index.get(...)`) |
| `ATTACKMappingBuilder` methods | `resolve`, `build`, `build_many` | `build`, `build_many` only |
| `attack_v19_core.mapping.V19_REVOCATION_MAP` | present (tests patch it) | absent / relocated |

Both builds label themselves `19.2.0`, so a naive version check would not have
caught the drift — only the commit SHA pin does. This is exactly why the engine
pins an **immutable commit** rather than a version range.

### The 13 failures, grouped by root cause (all one underlying cause)

`tests/test_revoked_id_handling.py` (11):
- `test_revoked_id_remapped_with_warning`, `test_revoked_parent_remapped_to_new_parent`,
  `test_revoked_subtechnique_remapped_to_new_subtechnique`, `test_revoked_log_clearing_remapped`
  — depended on the revocation map + resolution fields (`was_revoked`,
  `source_technique_id`, `resolved_technique_id`) present in the pinned build.
- `test_unknown_id_returns_none_logs_error`, `test_revoked_id_that_also_missing_returns_none`
  — depended on `attack_v19_core.mapping.V19_REVOCATION_MAP` and the `get_exact`
  "not found in index" path.
- `test_valid_id_returns_mapping` — asserted `tactic_id == "TA0002"`; the drifted
  build returned `"execution"`.
- `test_caller_must_filter_none`, `test_revocation_map_all_entries_resolvable`,
  `test_revoked_ids_resolve_through_revocation_map` — depended on `index.get()`.

`tests/test_product_telemetry_corpus.py` (4 parametrized cases):
- `_DeterministicAttackIndex` lacked `.get` because the drifted builder expected
  a different index protocol. Under the pinned build the deterministic index
  satisfies the real contract and all cases pass.

## Reproduction (clean environment)

```bash
# 1. Fetch and isolate the exact pinned commit
git -C <attack-v19-core-clone> fetch origin 087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b
git -C <attack-v19-core-clone> worktree add --detach /tmp/av19core-pinned \
    087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b

# 2. Build an isolated venv for the engine
cd attack-detection-engine
python3 -m venv .venv && . .venv/bin/activate
pip install /tmp/av19core-pinned          # pinned core
pip install pydantic PyYAML pytest pytest-cov "ruff==0.8.4"
pip install --no-deps -e .                 # the engine

# 3. Run (PYTEST_DISABLE_PLUGIN_AUTOLOAD only needed on hosts with conflicting
#    third-party pytest plugins such as ROS launch_testing; it is an
#    environment workaround, not a repository requirement)
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH= python -m pytest -q
ruff check detection_engine tests scripts .github/scripts
```

## Verified result (2026-10-27, Python 3.12.3, isolated venv, pinned core)

- `pytest` → **70 passed** (was 57 passed / 13 failed).
- Automotive/firmware/ARM subset → **31 passed** (regression preserved).
- `ruff 0.8.4 check` → **All checks passed**.

## Environment note (not a repository defect)

This host has ROS 2 (`/opt/ros/jazzy`) on the default `PYTHONPATH`, which
registers `launch_testing` / `launch_testing_ros` pytest plugins that are
incompatible with pytest 9 and break collection for *any* project on this
machine. The fix is environmental: run tests with
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=` (or inside a clean container as
the repo's CI already does). No repository code depends on this.
