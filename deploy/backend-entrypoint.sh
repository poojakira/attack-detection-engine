#!/usr/bin/env bash
# Backend container entrypoint: wait for PostgreSQL, apply migrations, then serve.
set -euo pipefail

: "${AEGIS_DATABASE_URL:?AEGIS_DATABASE_URL must be set}"
: "${AEGIS_JWT_SECRET:?AEGIS_JWT_SECRET must be set (do not use a default in deployment)}"

echo "[entrypoint] waiting for database..."
python - <<'PY'
import os, time, sys
from sqlalchemy import create_engine, text
url = os.environ["AEGIS_DATABASE_URL"]
for attempt in range(60):
    try:
        e = create_engine(url)
        with e.connect() as c:
            c.execute(text("SELECT 1"))
        e.dispose()
        print("[entrypoint] database reachable")
        sys.exit(0)
    except Exception as exc:
        print(f"[entrypoint] db not ready ({attempt}): {exc}")
        time.sleep(2)
print("[entrypoint] database never became reachable", file=sys.stderr)
sys.exit(1)
PY

echo "[entrypoint] applying Alembic migrations..."
cd /app/detection_engine/platform
alembic upgrade head
cd /app

echo "[entrypoint] seeding bootstrap admin if configured..."
echo "[entrypoint] starting uvicorn..."
exec uvicorn detection_engine.platform.server:app --host 0.0.0.0 --port 8000
