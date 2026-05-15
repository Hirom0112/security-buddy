"""Add offending_commit_hash for regression-run attribution.

Slice 6 DoD #3. Two nullable TEXT columns:

  - target_versions.commit_hash captures the merge_commit_sha that
    produced a given target deployment. Nullable because legacy rows
    pre-date this column.
  - regression_runs.offending_commit_hash is populated by the harness
    runner only when a replay aggregates to outcome='regressed'. For
    other outcomes (fix_verified, unstable, target_unavailable) the
    column stays NULL — only true regressions get attributed to a
    commit.

Forward-only per CLAUDE.md §9. downgrade() drops both columns.

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-15
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "target_versions",
        sa.Column("commit_hash", sa.Text(), nullable=True),
    )
    op.add_column(
        "regression_runs",
        sa.Column("offending_commit_hash", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("regression_runs", "offending_commit_hash")
    op.drop_column("target_versions", "commit_hash")
