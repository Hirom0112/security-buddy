"""Pre-write replay validation + response-shape dedup support.

The 22-vuln audit (PLAN.md "Documentation: pre-write 3-replay + response-shape
dedup") surfaced two operator-queue noise sources:

  1. Judge calls exploits aggressively. A vuln gets minted on a SINGLE
     successful verdict, with no validation that the attack reproduces.
  2. The deterministic mutator produced 9 lexical permutations of the same
     seed. All 9 returned identical response shapes. The Documentation Agent
     dutifully minted 9 separate findings. They were one bug.

This migration:

  - Adds `vulnerabilities.response_shape_hash TEXT NULL` (+ index) — populated
    at write time from a normalized hash of the target response. Used to
    detect a sibling variant within the same target_version.
  - Adds `vulnerabilities.variant_count INT NOT NULL DEFAULT 1` — bumped when
    a sibling attack hashes identically and is merged into an existing draft.
  - Adds `vulnerabilities.variant_of_vuln_id UUID NULL` — FK self-reference,
    reserved for future use where a merged variant gets its own row pointing
    back at the canonical finding (today we increment in place; this column
    keeps the option open).
  - Extends `verdicts.verdict` CHECK constraint to include 'replay_unstable',
    a terminal state for verdicts whose pre-write replay validation failed.
    Replay-unstable verdicts will not get reconsidered on retry.

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("response_shape_hash", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_vulnerabilities_response_shape_hash",
        "vulnerabilities",
        ["response_shape_hash"],
    )
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "variant_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "variant_of_vuln_id",
            UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_vulnerabilities_variant_of_vuln_id",
        "vulnerabilities",
        "vulnerabilities",
        ["variant_of_vuln_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # Extend verdicts.verdict CHECK to allow 'replay_unstable'. Postgres has
    # no ALTER CONSTRAINT for CHECKs — drop and recreate.
    op.drop_constraint("ck_verdicts_verdict", "verdicts", type_="check")
    op.create_check_constraint(
        "ck_verdicts_verdict",
        "verdicts",
        "verdict IN ('safe','exploit','partial','unclear','replay_unstable')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_verdicts_verdict", "verdicts", type_="check")
    op.create_check_constraint(
        "ck_verdicts_verdict",
        "verdicts",
        "verdict IN ('safe','exploit','partial','unclear')",
    )
    op.drop_constraint(
        "fk_vulnerabilities_variant_of_vuln_id",
        "vulnerabilities",
        type_="foreignkey",
    )
    op.drop_column("vulnerabilities", "variant_of_vuln_id")
    op.drop_column("vulnerabilities", "variant_count")
    op.drop_index(
        "ix_vulnerabilities_response_shape_hash",
        table_name="vulnerabilities",
    )
    op.drop_column("vulnerabilities", "response_shape_hash")
