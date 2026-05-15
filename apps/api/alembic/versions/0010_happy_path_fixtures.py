"""Happy-path fixtures + over-fit patch detection.

TODO.md "Product insight 2026-05-14" / Slice 6.5 — the regression harness
today only replays known *exploits*; an over-broad patch that blocks BOTH
the exploit AND the legitimate feature passes our check. VUL-0017's
patch broke the chatbox patient-census feature and the sweep didn't catch
it. This migration adds the schema needed to flip that gap:

  1. happy_path_fixtures table — canonical "legitimate clinician query +
     expected response shape" pairs, one row per target_manifest capability.
  2. regression_runs.kind column — distinguishes 'exploit_replay' (the
     existing behavior, default) from 'happy_path' (new).
  3. vulnerabilities.status += 'over_fit' — flipped when a patch fixes
     the security boundary but breaks a happy-path capability.
  4. patches.status += 'blocks_legit_features' — same signal, on the
     patch side.

Forward-only per CLAUDE.md §9. downgrade() reverses the additions.

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. happy_path_fixtures table.
    # ------------------------------------------------------------------
    op.create_table(
        "happy_path_fixtures",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_manifest_id", UUID(as_uuid=True), nullable=False),
        sa.Column("capability_name", sa.Text(), nullable=False),
        sa.Column("attack_input", sa.Text(), nullable=False),
        # expected_response_shape: JSONB with at minimum
        #   {"required_substrings": ["...", "..."]}
        # The harness checks each required_substring appears in the target's
        # response text. Intentionally lo-fi — we're catching over-fit
        # patches, not building a full conformance framework.
        sa.Column("expected_response_shape", JSONB(), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "version_id",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.ForeignKeyConstraint(
            ["target_manifest_id"],
            ["target_manifests.id"],
            name="fk_happy_path_fixtures_target_manifest_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "target_manifest_id",
            "capability_name",
            name="uq_happy_path_fixtures_manifest_capability",
        ),
    )
    op.create_index(
        "ix_happy_path_fixtures_manifest_enabled",
        "happy_path_fixtures",
        ["target_manifest_id", "enabled"],
    )

    # ------------------------------------------------------------------
    # 2. regression_runs.kind column.
    # 'exploit_replay' is the historical behavior; backfill default.
    # 'happy_path' is the new kind written by the over-fit detector.
    # ------------------------------------------------------------------
    op.add_column(
        "regression_runs",
        sa.Column(
            "kind",
            sa.Text(),
            nullable=False,
            server_default=sa.text("'exploit_replay'"),
        ),
    )
    op.create_check_constraint(
        "ck_regression_runs_kind",
        "regression_runs",
        "kind IN ('exploit_replay','happy_path')",
    )

    # ------------------------------------------------------------------
    # 3. vulnerabilities.status: add 'over_fit'.
    # 4. patches.status:         add 'blocks_legit_features'.
    # Postgres has no syntax for ALTER CHECK; drop and recreate.
    # ------------------------------------------------------------------
    op.drop_constraint("ck_vulnerabilities_status", "vulnerabilities", type_="check")
    op.create_check_constraint(
        "ck_vulnerabilities_status",
        "vulnerabilities",
        "status IN ('draft','open','proposed_fix','patched','regressed','unstable','over_fit')",
    )

    op.drop_constraint("ck_patches_status", "patches", type_="check")
    op.create_check_constraint(
        "ck_patches_status",
        "patches",
        "status IN ('awaiting_human_review','merged','rejected','ci_failed',"
        "'blocks_legit_features')",
    )


def downgrade() -> None:
    # Revert status check constraints.
    op.drop_constraint("ck_patches_status", "patches", type_="check")
    op.create_check_constraint(
        "ck_patches_status",
        "patches",
        "status IN ('awaiting_human_review','merged','rejected','ci_failed')",
    )
    op.drop_constraint("ck_vulnerabilities_status", "vulnerabilities", type_="check")
    op.create_check_constraint(
        "ck_vulnerabilities_status",
        "vulnerabilities",
        "status IN ('draft','open','proposed_fix','patched','regressed','unstable')",
    )

    op.drop_constraint("ck_regression_runs_kind", "regression_runs", type_="check")
    op.drop_column("regression_runs", "kind")

    op.drop_index(
        "ix_happy_path_fixtures_manifest_enabled",
        table_name="happy_path_fixtures",
    )
    op.drop_table("happy_path_fixtures")
