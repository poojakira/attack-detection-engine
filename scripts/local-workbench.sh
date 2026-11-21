#!/usr/bin/env bash
# First-party loopback-only development launcher. Requires Python 3.12, Node 22+
# and Docker. Persistent data belongs only to this named local workspace.
set -euo pipefail
cd "$(dirname "$0")/.."
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$PWD/.aegis-local/cache}"
export npm_config_cache="$XDG_CACHE_HOME/npm"
export PIP_CACHE_DIR="$XDG_CACHE_HOME/pip"
mkdir -p .aegis-local "$XDG_CACHE_HOME"
chmod 700 .aegis-local
if [[ ! -f .aegis-local/db-password ]]; then
  python3 - <<'PY'
import os, secrets
fd = os.open('.aegis-local/db-password', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write(secrets.token_hex(24))
PY
fi
export POSTGRES_PASSWORD
POSTGRES_PASSWORD=$(cat .aegis-local/db-password)
export AEGIS_DATABASE_URL="postgresql+psycopg://aegis:${POSTGRES_PASSWORD}@127.0.0.1:55432/aegis"
container=aegis-local-workbench-postgres
if docker container inspect "$container" >/dev/null 2>&1; then
  [[ "$(docker inspect -f '{{index .Config.Labels "aegis.local-workbench"}}' "$container")" == '1' ]] || { echo 'Container name is already owned by another task' >&2; exit 1; }
  docker start "$container" >/dev/null
else
  docker run -d --name "$container" --label aegis.local-workbench=1 \
    --memory 384m --cpus 1 --pids-limit 128 \
    -e POSTGRES_USER=aegis -e POSTGRES_DB=aegis -e POSTGRES_PASSWORD \
    -p 127.0.0.1:55432:5432 -v aegis-local-workbench-data:/var/lib/postgresql/data \
    postgres:17-alpine >/dev/null
fi
trap 'docker stop "$container" >/dev/null' EXIT
for attempt in {1..30}; do
  if docker exec "$container" pg_isready -U aegis -d aegis >/dev/null; then break; fi
  sleep 1
done
[[ -x .venv/bin/python ]] || python3 -m venv .venv
.venv/bin/python -m pip install -e '.[platform]'
npm --prefix dashboard-ui ci
npm --prefix dashboard-ui run build
.venv/bin/python -m detection_engine.platform.local --dashboard dashboard-ui/dist
