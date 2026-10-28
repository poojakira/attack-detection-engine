"""add user token_version for revocation

Revision ID: 53fef2dbf01d
Revises: 4295fbcefb96
Create Date: 2026-10-27

Adds users.token_version (default 0) used to revoke previously-issued tokens
(forced logout, role/org change). Minimal, reversible change.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "53fef2dbf01d"
down_revision: Union[str, Sequence[str], None] = "4295fbcefb96"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
