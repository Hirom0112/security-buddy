"""Add mode column to campaigns ('live' | 'smoke').

Distinguishes paid live runs (counted in the dashboard, billable) from
smoke runs (excluded from dashboard counts). Existing rows backfill to
'live' since this column is added on an empty runtime tables state after
the smoke-run truncate. The dashboard queries filter on mode = 'live',
so smoke campaigns appear on the /campaigns list but never inflate
coverage, attempts, or cost stats.

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column(
            "mode",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'live'"),
        ),
    )
    op.create_check_constraint(
        "ck_campaigns_mode",
        "campaigns",
        "mode IN ('live', 'smoke')",
    )
    op.create_index(
        "ix_campaigns_mode_created_at",
        "campaigns",
        ["mode", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_campaigns_mode_created_at", table_name="campaigns")
    op.drop_constraint("ck_campaigns_mode", "campaigns", type_="check")
    op.drop_column("campaigns", "mode")
