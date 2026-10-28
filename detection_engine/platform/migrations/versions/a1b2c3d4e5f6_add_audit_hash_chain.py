"""add tamper-evident audit hash chain columns

Revision ID: a1b2c3d4e5f6
Revises: 53fef2dbf01d
Create Date: 2026-10-27

Adds chain_seq / prev_hash / entry_hash to investigation_actions for a
per-organization tamper-evident hash chain. Existing rows get seq 0 and empty
hashes (historical records predating the chain remain readable).
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "53fef2dbf01d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "investigation_actions",
        sa.Column("chain_seq", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "investigation_actions",
        sa.Column("prev_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "investigation_actions",
        sa.Column("entry_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.create_index(
        "ix_investigation_actions_chain_seq", "investigation_actions", ["chain_seq"]
    )


def downgrade() -> None:
    op.drop_index("ix_investigation_actions_chain_seq", table_name="investigation_actions")
    op.drop_column("investigation_actions", "entry_hash")
    op.drop_column("investigation_actions", "prev_hash")
    op.drop_column("investigation_actions", "chain_seq")
