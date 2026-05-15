"""Add patches.attempt_number for auto-retry on unstable regressions.

Slice — Auto-retry on unstable regression:
  When a patch's regression sweep aggregates to UNSTABLE or REGRESSED, the
  harness worker enqueues a second patch attempt with the prior diff +
  failing replay payloads folded into the prompt. Cap is 2 attempts total
  per vulnerability (attempt #1 = initial patch, attempt #2 = first retry);
  after attempt #2 lands bad, the vuln waits for a human.

Schema changes:
  1. Add `patches.attempt_number INT NOT NULL DEFAULT 1`. Backfilling
     existing rows to 1 is correct — every pre-existing patch was the
     initial attempt.
  2. Drop the partial unique index `ix_patches_vulnerability_id_active`
     (introduced by 0005) which forbade two ACTIVE patches per vuln.
     Replace it with a partial unique on (vulnerability_id, attempt_number)
     so attempt #1 (now SUPERSEDED) and attempt #2 (active) can coexist
     in the active set.
  3. Extend `ck_patches_status` to admit the new SUPERSEDED status used
     when attempt #1 is auto-superseded by attempt #2.

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-15
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. attempt_number column.
    op.add_column(
        "patches",
        sa.Column(
            "attempt_number",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )

    # 2. Replace the per-vuln "one active patch" index with one that
    #    keys on (vulnerability_id, attempt_number). Two attempts per
    #    vuln are now permitted; same attempt_number is not.
    op.drop_index("ix_patches_vulnerability_id_active", table_name="patches")
    op.create_index(
        "ix_patches_vuln_attempt_active",
        "patches",
        ["vulnerability_id", "attempt_number"],
        unique=True,
        postgresql_where="status IN ('awaiting_human_review','merged','superseded')",
    )

    # 3. CHECK constraint update — admit SUPERSEDED.
    op.drop_constraint("ck_patches_status", "patches", type_="check")
    op.create_check_constraint(
        "ck_patches_status",
        "patches",
        "status IN ('awaiting_human_review','merged','rejected','ci_failed',"
        "'blocks_legit_features','superseded')",
    )


def downgrade() -> None:
    # Revert CHECK constraint.
    op.drop_constraint("ck_patches_status", "patches", type_="check")
    op.create_check_constraint(
        "ck_patches_status",
        "patches",
        "status IN ('awaiting_human_review','merged','rejected','ci_failed',"
        "'blocks_legit_features')",
    )

    # Revert index back to the pre-0012 shape.
    op.drop_index("ix_patches_vuln_attempt_active", table_name="patches")
    op.create_index(
        "ix_patches_vulnerability_id_active",
        "patches",
        ["vulnerability_id"],
        unique=True,
        postgresql_where="status IN ('awaiting_human_review','merged')",
    )

    op.drop_column("patches", "attempt_number")
