"""Loopback launch for an installed backend and prebuilt React dashboard.

The caller supplies a local PostgreSQL URL; this module never creates cloud
resources or reads arbitrary upload paths. Applies real Alembic migrations.
"""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dashboard",
        type=Path,
        required=True,
        help="Trusted prebuilt dashboard-ui/dist directory",
    )
    parser.add_argument("--username", default="local-analyst")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read initial local password from stdin, for isolated automation",
    )
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not os.environ.get("AEGIS_DATABASE_URL", "").startswith("postgresql+psycopg://"):
        parser.error(
            "set AEGIS_DATABASE_URL to your isolated local PostgreSQL database"
        )
    if not (args.dashboard / "index.html").is_file():
        parser.error(
            "dashboard is not built; run npm ci and npm run build in dashboard-ui"
        )
    password = (
        input()
        if args.password_stdin
        else getpass.getpass("Initial local analyst password (12+ characters): ")
    )
    if len(password) < 12:
        parser.error("initial password must be at least 12 characters")
    # Per-process signing secret, never printed or stored; tokens expire on restart.
    os.environ.setdefault("AEGIS_JWT_SECRET", os.urandom(32).hex())
    os.environ["AEGIS_CORS_ORIGINS"] = (
        f"http://127.0.0.1:{args.port},http://localhost:{args.port}"
    )
    from alembic import command
    from alembic.config import Config
    from starlette.staticfiles import StaticFiles
    import uvicorn
    from . import db
    from .api import create_app
    from .bootstrap import seed_user

    cfg = Config(str(Path(__file__).with_name("alembic.ini")))
    command.upgrade(cfg, "head")
    engine = db.make_engine()
    with db.make_session_factory(engine)() as session:
        seed_user(
            session,
            user_id="local-analyst",
            username=args.username,
            password=password,
            role="administrator",
            organization_id="local-investigations",
        )
    engine.dispose()
    del password
    app = create_app()
    app.mount("/", StaticFiles(directory=args.dashboard, html=True), name="dashboard")
    print(
        f"Local workbench: http://127.0.0.1:{args.port} (username: {args.username})",
        flush=True,
    )
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=args.port,
        limit_concurrency=20,
        timeout_keep_alive=5,
    )


if __name__ == "__main__":
    main()
