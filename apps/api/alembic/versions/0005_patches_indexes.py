"""Add idempotency indexes for patches.

Slice 5: one in-flight patch per vulnerability. The Patch worker keys arq
job dedup on vulnerability_id; the unique index is defence-in-depth so a
retried job that races past arq's deduplication cannot insert a duplicate
patches row.

A separate index on branch_name accelerates the webhook lookup that maps
a merged PR's head branch back to its patches row (Slice 6 wires this).

Revision ID: 0005_patches_indexes
Revises: 0004_seed_target_manifest
Create Date: 2026-05-12
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0005_patches_indexes"
down_revision: str | None = "0004_seed_target_manifest"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_patches_vulnerability_id_active",
        "patches",
        ["vulnerability_id"],
        unique=True,
        postgresql_where="status IN ('awaiting_human_review','merged')",
    )
    op.create_index(
        "ix_patches_branch_name",
        "patches",
        ["branch_name"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_patches_branch_name", table_name="patches")
    op.drop_index("ix_patches_vulnerability_id_active", table_name="patches")
