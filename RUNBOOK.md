# Runbook

## Important: Sibling Dependency

This package depends on the versioned `attack-v19-core` package. Install from PyPI for normal use; a sibling checkout is only needed when developing both repositories together:

```bash
pip install "attack-v19-core>=19.2,<20"
pip install -e ".[dev]"

# Optional: when developing both repositories together, install the sibling
# checkout editable before installing this project.
```

`pip install -e ".[dev]"` resolves `attack-v19-core` from the configured package index. CI may still use an explicit checkout when validating unreleased cross-repository changes.

## Build Commands

| Command | What it does |
|---------|--------------|
| `make install` | Install dependencies and the package in editable mode |
| `make install-core` | Install `attack-v19-core` from the sibling directory (`../attack-v19-core`) |
| `make data` | Download pinned STIX ATT&CK data via `attack-v19-core` script |
| `make lint` | Run ruff linter |
| `make format` | Run ruff formatter |
| `make test` | Run pytest (installs core + downloads data first) |
| `make build` | Build the wheel package |
| `make security` | Run bandit SAST scan and pip-audit dependency check |
| `make verify` | Run lint, test, build, and security in sequence |

## Dashboard

There is a static HTML dashboard at `dashboard/index.html`. You can serve it locally with:

```bash
make dashboard
```

This starts a Python HTTP server on port 8080. The dashboard is a visualization tool, not a runtime component.

## Dependencies

- `attack-v19-core>=19.2,<20` is the runtime taxonomy dependency. Production images pin an immutable core source revision; normal package installs use the released package.
- STIX data is downloaded and pinned during the `make data` step.

## What Has Been Validated Locally

- Ruff linting passed at the documented local-validation snapshot.
- The older local snapshot recorded 27 pytest cases passing.
- Current source contains 23 test functions and pytest collects 29 cases (because one test is parametrized); do not describe all 29 as passing until the current suite is rerun.
- Wheel build succeeded at the documented local-validation snapshot.

## What Has NOT Been Validated Locally

- Linux compatibility (only tested in CI after push)
- Full CI pipeline results (GitHub Actions)
- Dependency vulnerability status may change after any local snapshot
- No runtime or production testing has been done — this is a library, not a deployed service