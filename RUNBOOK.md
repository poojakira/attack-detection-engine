# Local operations and developer runbook

## Choose the correct surface

| Surface | Entry point | Boundary |
|---|---|---|
| Local browser workbench | `./scripts/local-workbench.sh` | Authenticated React/API with dedicated PostgreSQL and synthetic FHIR investigations |
| Installed backend plus trusted dashboard build | `python -m detection_engine.platform.local --dashboard PATH --port NUMBER` | Operator-supplied local PostgreSQL; loopback API, migrations and local user seed |
| Separate deployment ASGI app | `uvicorn detection_engine.platform.server:app` | Explicit deployment configuration and independently reviewed network/storage controls |
| Offline NDJSON CLI | `attack-detect --input FILE --output FILE --fail-on high` | Supplied telemetry; findings, not prevention or a live collector |
| Legacy static dashboard | `make dashboard` | Static visualization, not the React investigation workflow or execution evidence |

## Local startup and shutdown

Use [README prerequisites](README.md#start-locally). The script creates `aegis-local-workbench-postgres` with an ownership label and `aegis-local-workbench-data`, publishes PostgreSQL only on `127.0.0.1:55432`, applies migrations and starts the API/dashboard on loopback 8000. It stores a random development database password in `.aegis-local/db-password` with mode 0600; keep this private file paired with its database volume. Do not copy its value into reports or chat.

The script has no port argument. For an occupied/managed port, use the supported module's `--port` with a prebuilt trusted dashboard and an already configured isolated local PostgreSQL URL. Obtain database/auth secrets through your approved local configuration; this guide does not print shared values:

```sh
python -m detection_engine.platform.local --help
python -m detection_engine.platform.local --dashboard /absolute/path/dashboard-ui/dist --port 8764
```

The module prompts for the initial local password; it does not reset an existing account. It seeds username `local-analyst` as administrator in `local-investigations`, applies Alembic and creates a per-process signing secret unless explicitly configured. A restart invalidates tokens created under that ephemeral secret; sign in again. The local module expects `AEGIS_DATABASE_URL` to use the `postgresql+psycopg://` driver and a trusted built dashboard. It does not create cloud resources or a database server.

Ctrl-C stops the owned API; the script's exit trap stops its named container. The volume and private password file retain data. Normal stop/start is persistence, not tested production backup/restore. Stop only your own processes; do not terminate all PostgreSQL backends or every Python process. If a disposable test hangs on a lock, identify the owning test/session and coordinate its termination; never use a blanket database-wide kill as normal recovery.

## Data lifecycle and diagnostics

Original input JSON, normalized events, findings/incidents and immutable run reports persist in PostgreSQL. Exports include original supplied fields and can disclose identifiers. No privacy classifier or anonymization proof exists. Treat database files, reports, backups and private configuration as sensitive; synthetic data is required for this evaluation. Browser auth state is memory/sessionStorage, not report content.

```sh
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/readiness
```

Health is liveness/provenance metadata. Readiness queries PostgreSQL and returns 503 on failure without a connection string. Neither validates detection efficacy or production security. [API errors and recovery](docs/WORKBENCH.md#api-contract) distinguish bad input, stale reruns, authorization, quotas and engine failure. Browser cancellation can leave a committed case/run; reload saved investigations before deciding whether to retry.

For retention/deletion, export only permitted data and obtain the owner's explicit approval before removing the dedicated container, volume or `.aegis-local`. Deleting only the password file while retaining the volume can break future authentication. No automatic purge or production retention guarantee is provided.

## Offline CLI and pipeline

`pyproject.toml` and `requirements.txt` pin core commit `087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b`; a broad `attack-v19-core>=19.2` install is not the reproducible project setup. `requirements.lock` records the tested dependency snapshot; direct pins, build tooling and mutable image tags do not by themselves establish complete hermetic reproduction. ATT&CK-dependent paths need checksum-verified v19.2 bundles in `ATTACK_DATA_DIR`.

```sh
attack-detect --help
printf '%s\n' '{}' | attack-detect --input - --output - --fail-on high
```

The empty object is a synthetic benign control, not proof that a host is clean. CLI input is NDJSON: each UTF-8 line has a 1 MiB byte limit, including its terminator if present. Nonblank lines must be JSON objects. Supported source keys are `logs`, `traffic`, `behaviors`, `events`, `code`, `automotive_can`, `firmware`, `arm_binary` and `clinical_access`; each supplied source is a list of objects, by default at most 10,000 records. Unknown keys fail. CLI `--fail-on` defaults to `never`; exit 0 therefore does not establish absence of findings or safety. Configured threshold findings yield exit 1; caught input/I/O errors yield exit 2. Other initialization failures may propagate; preserve stderr rather than inventing a successful scan.

`arm_binary` requires actual bytes in the Python API, which ordinary NDJSON cannot encode directly. There is no documented implicit base64 decoder. Use the [separate offline examples](AUTOMOTIVE_SECURITY.md). CLI output is NDJSON: each accepted input object produces an envelope with `line`, `finding_count` and a `findings` list, including an empty list for the benign control. This is separate from the authenticated workbench's case/run report.

## Run the CLI image

Build the root Dockerfile with the pinned core revision. Supply the verified data directory to the runtime user through a read-only mount.

```sh
ATTACK_CORE_REF=087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b
docker build --build-arg "ATTACK_CORE_REF=$ATTACK_CORE_REF" -t aegis-detection-cli .
python -m attack_v19_core.download --data-dir "$ATTACK_DATA_DIR"
printf '%s\n' '{}' | docker run --rm -i \
  --mount "type=bind,src=$ATTACK_DATA_DIR,dst=/attack-data,readonly" \
  --env ATTACK_DATA_DIR=/attack-data aegis-detection-cli
```

Set `ATTACK_DATA_DIR` to an absolute directory that the container runtime user can read. The CLI image and the separate workbench deployment have distinct entry points.

## Develop and verify safely

[Workbench checks](docs/WORKBENCH.md#testing-evidence-and-security-autopsy) specify complete dependencies, real disposable PostgreSQL and ATT&CK prerequisites. Tests using `pg_engine` **drop all ORM tables** before and after execution. Never target the retained local product volume, user data or a deployment database. Set both database variables explicitly to an isolated disposable database; the test fixture has an unsafe-to-assume default, so verify your environment first.

`make test` installs a sibling `ATTACK_CORE_PATH` and downloads data via that checkout; it does not guarantee the project pin. Review/pin the sibling before invoking it. `make data` also requires that sibling path. `make format` mutates source. `make install` installs packages and upgrades pip. These are developer conveniences, not all equivalent to the frozen-candidate verification procedure. The primary workbench guide uses explicit commands and out-of-tree evidence.

Some optional STIX tooling writes at its default HOME. Do not override a managed read-only HOME. Use an isolated nonroot runtime with an ephemeral writable mount at that runtime's existing default HOME. Missing PostgreSQL/data/optional prerequisites must appear as skips/blockers, not passing tests. Source headers, runtime/API contracts and timestamps in final artifacts identify the actual candidate.

## Separate Compose deployment and rollback

`deploy/docker-compose.yml` is an optional deployment configuration, not the local launch script. It requires operator-owned `AEGIS_DB_PASSWORD`, a strong `AEGIS_JWT_SECRET`, and suitable bootstrap/admin configuration. Compose does not publish PostgreSQL to the host; backend/frontend dev ports bind loopback. The backend secure-config gate is enabled there. Its PostgreSQL version/image, Dockerfiles, mutable base tags, runtime HOME mount and target network/storage require independent review. No current product-container deployment or production approval is established by this documentation pass.

The backend entrypoint applies migrations. Before rollback, stop writers and preserve an owner-approved compatible backup. Migration `b2c3d4e5f6a7` downgrade drops workbench case/run tables; do not run it blindly. Use a separate reviewed checkout/environment or validated immutable image and rerun authentication, negative cases and the permitted task. Code rollback does not revoke credentials, erase exports or restore previously deleted data. Formal backup/restore, capacity, TLS/SSO/secret management and operational recovery require an environment-specific exercised plan.
