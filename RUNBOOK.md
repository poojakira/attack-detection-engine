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
- The automotive-focused suite (`tests/test_automotive_embedded.py`, `tests/test_automotive_evidence.py`, `tests/test_automotive_pipeline.py`) passed **29 cases** on Windows Python 3.12 after the merge, October 15, 2026. This is *not* the full repository test count. Previously noted 23-function/29-case totals are superseded by later code additions.
- Wheel build succeeded at the documented local-validation snapshot.

## What Has NOT Been Validated Locally

- Linux compatibility (only tested in CI after push)
- Full CI pipeline results (GitHub Actions)
- Dependency vulnerability status may change after any local snapshot
- No runtime or production testing has been done — this is a library, not a deployed service

## Embedded/automotive offline regression (October 2026)

```bash
python -m pytest -q tests/test_automotive_embedded.py tests/test_automotive_evidence.py tests/test_automotive_pipeline.py
python -m pytest -q
python -m ruff check detection_engine tests
```

Cortex-M3 reproducible build and intentional sanitizer overflow/remediation evidence:
[AUTOMOTIVE_SECURITY.md](AUTOMOTIVE_SECURITY.md). The ELF example was built with
`arm-none-eabi-gcc` in Ubuntu WSL2; an isolated deliberately vulnerable native
C fixture was confirmed by AddressSanitizer. No tests were performed against
a production ECU, live vehicle network, or customer system.

Full-suite tests that load the ATT&CK STIX dataset repeatedly may be
substantially slower than the focused suite. Do not equate a slow,
unfinished run with success or a code defect; always record completion,
exit code and failures separately.

## Full suite performance and repeatability, October 15, 2026

Legacy tests now use a session-scoped shared ttack_index fixture in 	ests/conftest.py rather than repeatedly rebuilding large ATT&CK indexes. Run python -m pytest -q; a Windows Python 3.12.13 full-suite execution passed **68/68 in 25.92 seconds**. This supersedes earlier notes that full-suite completion was unverified. Hardware ECU testing remains unperformed because no CAN, serial or debug adapter was detected on the connected Windows machine.


## Milestone C: Investigation platform runbook (October 27, 2026)

### Local development (API + PostgreSQL)

```bash
# 1. Install the platform extras into a venv with the pinned core
python3 -m venv .venv && . .venv/bin/activate
pip install .            # pulls the pinned attack-v19-core commit
pip install ".[platform]" "ruff==0.8.4"

# 2. Start a PostgreSQL for development/tests
docker run -d --name aegis-pg -e POSTGRES_PASSWORD=aegis -e POSTGRES_USER=aegis \
  -e POSTGRES_DB=aegis -p 55432:5432 postgres:15

# 3. Apply migrations
export AEGIS_DATABASE_URL="postgresql+psycopg://aegis:aegis@127.0.0.1:55432/aegis"
( cd detection_engine/platform && alembic upgrade head )

# 4. Run the platform tests (real PostgreSQL)
export AEGIS_JWT_SECRET="dev-secret"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH= python -m pytest -q \
  tests/test_platform_db.py tests/test_platform_api_e2e.py
```

### Full containerized deployment

```bash
export AEGIS_JWT_SECRET=$(openssl rand -hex 32)
export AEGIS_ADMIN_USER=admin AEGIS_ADMIN_PASSWORD=choose-a-password
docker compose -f deploy/docker-compose.yml up --build
# API http://localhost:8000 (/docs), dashboard http://localhost:8080
```

### Frontend build

```bash
cd dashboard-ui && npm ci && npm run build   # outputs dist/
```

### Operational note: stuck PostgreSQL locks

A cancelled test run can leave a Python process holding an
`idle in transaction` lock, which blocks `DROP TABLE` in the next test's setup
indefinitely. If DB tests appear to hang, clear lingering backends:

```bash
PGPASSWORD=aegis psql -U aegis -h 127.0.0.1 -p 55432 -d aegis -c \
 "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
  WHERE datname='aegis' AND pid<>pg_backend_pid();"
```

The ATT&CK index parse is ~9s; it is cached per process. A slow full-suite run
is expected — record completion, exit code, and failures separately.
