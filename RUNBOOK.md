# Runbook

## Important: Sibling Dependency

This package depends on `attack-v19-core` which is NOT on PyPI. You must install it from the sibling repo first:

```bash
# Clone both repos side by side
git clone https://github.com/poojakira/attack-v19-core.git
git clone https://github.com/poojakira/attack-detection-engine.git

# Install attack-v19-core first
cd attack-v19-core
pip install -e .
cd ..

# Then install this package
cd attack-detection-engine
pip install -e ".[dev]"
```

Running `pip install -e ".[dev]"` alone **will fail** with: `Could not find a version that satisfies the requirement attack-v19-core>=19.1.0`

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

- `attack-v19-core` is required at runtime. CI checks it out using `ATTACK_CORE_TOKEN`.
- STIX data is downloaded and pinned during the `make data` step.

## What Has Been Validated Locally

- Ruff linting passes
- 27 pytest tests pass
- Wheel build succeeds

## What Has NOT Been Validated Locally

- Linux compatibility (only tested in CI after push)
- Full CI pipeline results (GitHub Actions)
- Dependency vulnerability status may change after any local snapshot
- No runtime or production testing has been done — this is a library, not a deployed service
