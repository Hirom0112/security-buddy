"""core_schema

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-11 00:00:01.000000

Full core schema for Security Buddy (Slice 0 deliverable #6).

This is the EXPANDED version as specified in PLAN.md Slice 0 deliverable #6:
  - attack_taxonomy includes framework_mappings JSONB + framework_versions JSONB
  - vulnerabilities includes owasp_llm_id, mitre_atlas_technique_id, hipaa_safeguard,
    and framework_versions JSONB (snapshotted at confirmation time per CLAUDE.md §6a)

Table notes:
  - target_versions uses target_manifest_id UUID FK (cleaner than FK on the unique text
    target_id column; avoids the ambiguity of FKing to a non-PK column)
  - All UUID PKs use gen_random_uuid() via pgcrypto extension (enabled at top of upgrade)
  - version_id columns implement optimistic locking (CLAUDE.md §9)
  - All list endpoints will enforce pagination at the application layer (CLAUDE.md §9);
    no unbounded queries are issued by the ORM
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Enable pgcrypto so gen_random_uuid() is available as a column default.
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # -------------------------------------------------------------------------
    # attack_taxonomy
    # The graph of what gets attacked and why. Seeded by migration 0003.
    # framework_mappings example:
    #   {"owasp_llm": "LLM01:2025", "mitre_atlas": "AML.T0051.001",
    #    "hipaa": ["164.312(a)(1)", "164.312(c)(1)"]}
    # framework_versions example:
    #   {"owasp_llm": "2025-v2.0", "mitre_atlas": "5.1.0", "hipaa": "2013-omnibus"}
    # -------------------------------------------------------------------------
    op.create_table(
        "attack_taxonomy",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("subcategory", sa.Text(), nullable=False),
        sa.Column(
            "priority",
            sa.Text(),
            nullable=False,
        ),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("framework_mappings", JSONB(), nullable=False),
        sa.Column("framework_versions", JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "priority IN ('critical','high','medium','low')",
            name="ck_attack_taxonomy_priority",
        ),
        sa.UniqueConstraint("subcategory", name="uq_attack_taxonomy_subcategory"),
    )

    # -------------------------------------------------------------------------
    # target_manifests
    # Stores the declared capability surface of each target system.
    # -------------------------------------------------------------------------
    op.create_table(
        "target_manifests",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("manifest_json", JSONB(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("target_id", name="uq_target_manifests_target_id"),
    )

    # -------------------------------------------------------------------------
    # target_versions
    # Each row records one observed deployment of a target.
    # FK is to target_manifests.id (UUID), not to target_manifests.target_id
    # (TEXT), so the FK references the PK — cleaner, avoids FKing to a
    # non-PK column, and lets manifests be updated without orphaning versions.
    # -------------------------------------------------------------------------
    op.create_table(
        "target_versions",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("target_manifest_id", UUID(as_uuid=True), nullable=False),
        # Denormalized target_id for efficient lookup without join.
        sa.Column("target_id", sa.Text(), nullable=False),
        sa.Column("version", sa.Text(), nullable=False),
        sa.Column("deployed_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("triggered_by", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["target_manifest_id"],
            ["target_manifests.id"],
            name="fk_target_versions_target_manifest_id",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("target_id", "version", name="uq_target_versions_target_id_version"),
    )

    # -------------------------------------------------------------------------
    # campaigns
    # Lifecycle: pending → in_progress → completed | halted | budget_warning
    #            | budget_exhausted | no_candidates
    # version_id: optimistic locking (CLAUDE.md §9)
    # -------------------------------------------------------------------------
    op.create_table(
        "campaigns",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("budget_usd", sa.Numeric(10, 4), nullable=False),
        sa.Column("target_version_id", UUID(as_uuid=True), nullable=True),
        sa.Column("target_subcategory", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "version_id",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','in_progress','completed','halted',"
            "'budget_warning','budget_exhausted','no_candidates')",
            name="ck_campaigns_status",
        ),
        sa.ForeignKeyConstraint(
            ["target_version_id"],
            ["target_versions.id"],
            name="fk_campaigns_target_version_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["target_subcategory"],
            ["attack_taxonomy.subcategory"],
            name="fk_campaigns_target_subcategory",
            ondelete="RESTRICT",
        ),
    )

    # -------------------------------------------------------------------------
    # campaign_briefs
    # One brief per campaign (one-to-one for MVP; the schema allows many).
    # Lifecycle: pending → in_progress → completed
    # -------------------------------------------------------------------------
    op.create_table(
        "campaign_briefs",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("campaign_id", UUID(as_uuid=True), nullable=False),
        sa.Column("target_subcategory", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("variant_count", sa.Integer(), nullable=False),
        sa.Column("success_criteria", JSONB(), nullable=False),
        sa.Column("budget_usd", sa.Numeric(10, 4), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "variant_count > 0",
            name="ck_campaign_briefs_variant_count_positive",
        ),
        sa.CheckConstraint(
            "status IN ('pending','in_progress','completed')",
            name="ck_campaign_briefs_status",
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name="fk_campaign_briefs_campaign_id",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["target_subcategory"],
            ["attack_taxonomy.subcategory"],
            name="fk_campaign_briefs_target_subcategory",
            ondelete="RESTRICT",
        ),
    )

    # -------------------------------------------------------------------------
    # attacks
    # Every attack payload and its target response. Lifecycle:
    # pending_execution → awaiting_judgment → judged | target_unavailable
    # -------------------------------------------------------------------------
    op.create_table(
        "attacks",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("campaign_id", UUID(as_uuid=True), nullable=False),
        sa.Column("brief_id", UUID(as_uuid=True), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("subcategory", sa.Text(), nullable=False),
        sa.Column("mutation_strategy", sa.Text(), nullable=False),
        sa.Column("seed_used", sa.Text(), nullable=True),
        sa.Column("attack_input", sa.Text(), nullable=False),
        sa.Column(
            "attack_metadata",
            JSONB(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
        sa.Column("target_response", sa.Text(), nullable=True),
        sa.Column("target_response_status", sa.Integer(), nullable=True),
        sa.Column("target_response_time_ms", sa.Integer(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("executed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending_execution','awaiting_judgment','judged','target_unavailable')",
            name="ck_attacks_status",
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name="fk_attacks_campaign_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["brief_id"],
            ["campaign_briefs.id"],
            name="fk_attacks_brief_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["subcategory"],
            ["attack_taxonomy.subcategory"],
            name="fk_attacks_subcategory",
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        "ix_attacks_campaign_id_status",
        "attacks",
        ["campaign_id", "status"],
    )
    op.create_index(
        "ix_attacks_subcategory_status",
        "attacks",
        ["subcategory", "status"],
    )

    # -------------------------------------------------------------------------
    # verdicts
    # One verdict per attack, ever (unique constraint on attack_id).
    # Terminal table — no status column; the row IS the verdict.
    # -------------------------------------------------------------------------
    op.create_table(
        "verdicts",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("attack_id", UUID(as_uuid=True), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Numeric(3, 2), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("rubric_version", sa.Text(), nullable=False),
        sa.Column("model_version", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "verdict IN ('safe','exploit','partial','unclear')",
            name="ck_verdicts_verdict",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_verdicts_confidence_range",
        ),
        sa.UniqueConstraint("attack_id", name="uq_verdicts_attack_id"),
        sa.ForeignKeyConstraint(
            ["attack_id"],
            ["attacks.id"],
            name="fk_verdicts_attack_id",
            ondelete="RESTRICT",
        ),
    )

    # -------------------------------------------------------------------------
    # vulnerabilities
    # Confirmed exploits as structured reports. EXPANDED version (PLAN.md §6):
    #   - owasp_llm_id, mitre_atlas_technique_id, hipaa_safeguard: top-level
    #     columns for fast queries and GRC export
    #   - framework_versions JSONB: snapshot of framework versions at time of
    #     confirmation (CLAUDE.md §6a — regression harness uses the snapshot,
    #     not the current taxonomy)
    #   - rubric_snapshot JSONB: frozen rubric (populated in Slice 4+)
    # Lifecycle: draft → open → proposed_fix → patched | regressed | unstable
    # version_id: optimistic locking
    # -------------------------------------------------------------------------
    op.create_table(
        "vulnerabilities",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("vuln_id", sa.Text(), nullable=False),
        sa.Column("attack_id", UUID(as_uuid=True), nullable=False),
        sa.Column("verdict_id", UUID(as_uuid=True), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("clinical_impact", sa.Text(), nullable=False),
        sa.Column("reproduction_steps", sa.Text(), nullable=False),
        sa.Column("observed_behavior", sa.Text(), nullable=False),
        sa.Column("expected_behavior", sa.Text(), nullable=False),
        sa.Column("recommended_remediation", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        # Framework columns — mandatory, non-negotiable per PLAN.md Slice 0 #6
        sa.Column("owasp_llm_id", sa.Text(), nullable=False),
        sa.Column("mitre_atlas_technique_id", sa.Text(), nullable=False),
        sa.Column("hipaa_safeguard", sa.Text(), nullable=False),
        sa.Column("framework_versions", JSONB(), nullable=False),
        sa.Column("target_version_id", UUID(as_uuid=True), nullable=True),
        # rubric_snapshot: frozen rubric at confirmation time; populated in Slice 4.
        sa.Column("rubric_snapshot", JSONB(), nullable=True),
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
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low')",
            name="ck_vulnerabilities_severity",
        ),
        sa.CheckConstraint(
            "status IN ('draft','open','proposed_fix','patched','regressed','unstable')",
            name="ck_vulnerabilities_status",
        ),
        sa.UniqueConstraint("vuln_id", name="uq_vulnerabilities_vuln_id"),
        sa.ForeignKeyConstraint(
            ["attack_id"],
            ["attacks.id"],
            name="fk_vulnerabilities_attack_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["verdict_id"],
            ["verdicts.id"],
            name="fk_vulnerabilities_verdict_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_version_id"],
            ["target_versions.id"],
            name="fk_vulnerabilities_target_version_id",
            ondelete="SET NULL",
        ),
    )

    # -------------------------------------------------------------------------
    # patches
    # Proposed code fixes as GitHub pull requests. Lifecycle:
    # awaiting_human_review → merged | rejected | ci_failed
    # version_id: optimistic locking
    # -------------------------------------------------------------------------
    op.create_table(
        "patches",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("vulnerability_id", UUID(as_uuid=True), nullable=False),
        sa.Column("branch_name", sa.Text(), nullable=False),
        sa.Column("pr_url", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("merged_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "version_id",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
        sa.CheckConstraint(
            "status IN ('awaiting_human_review','merged','rejected','ci_failed')",
            name="ck_patches_status",
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name="fk_patches_vulnerability_id",
            ondelete="RESTRICT",
        ),
    )

    # -------------------------------------------------------------------------
    # regression_runs
    # Records the outcome of replaying confirmed exploits after a patch merge.
    # verdicts column: JSONB array of per-replay verdict objects.
    # Outcome: fix_verified | regressed | unstable | target_unavailable
    # -------------------------------------------------------------------------
    op.create_table(
        "regression_runs",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("vulnerability_id", UUID(as_uuid=True), nullable=False),
        sa.Column("target_version_id", UUID(as_uuid=True), nullable=False),
        sa.Column("replay_count", sa.Integer(), nullable=False),
        sa.Column("verdicts", JSONB(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("triggered_by", sa.Text(), nullable=False),
        sa.Column(
            "started_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "replay_count > 0",
            name="ck_regression_runs_replay_count_positive",
        ),
        sa.CheckConstraint(
            "outcome IN ('fix_verified','regressed','unstable','target_unavailable')",
            name="ck_regression_runs_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
            name="fk_regression_runs_vulnerability_id",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_version_id"],
            ["target_versions.id"],
            name="fk_regression_runs_target_version_id",
            ondelete="RESTRICT",
        ),
    )

    # -------------------------------------------------------------------------
    # agent_traces
    # Every LLM call logged for cost tracking and observability.
    # The Orchestrator queries this table to enforce campaign budget caps.
    # -------------------------------------------------------------------------
    op.create_table(
        "agent_traces",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("agent", sa.Text(), nullable=False),
        sa.Column("request_id", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=False),
        sa.Column("prompt_hash", sa.Text(), nullable=False),
        sa.Column("completion_hash", sa.Text(), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=False),
        sa.Column("tokens_out", sa.Integer(), nullable=False),
        sa.Column("cost_usd", sa.Numeric(12, 6), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("campaign_id", UUID(as_uuid=True), nullable=True),
        sa.Column("attack_id", UUID(as_uuid=True), nullable=True),
        sa.Column("verdict_id", UUID(as_uuid=True), nullable=True),
        sa.Column(
            "started_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "agent IN ('orchestrator','red_team','judge','documentation','patch')",
            name="ck_agent_traces_agent",
        ),
        sa.CheckConstraint(
            "outcome IN ('success','failure','timeout','refusal')",
            name="ck_agent_traces_outcome",
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaigns.id"],
            name="fk_agent_traces_campaign_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["attack_id"],
            ["attacks.id"],
            name="fk_agent_traces_attack_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["verdict_id"],
            ["verdicts.id"],
            name="fk_agent_traces_verdict_id",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_agent_traces_campaign_id",
        "agent_traces",
        ["campaign_id"],
    )
    op.create_index(
        "ix_agent_traces_agent_started_at",
        "agent_traces",
        ["agent", "started_at"],
    )


def downgrade() -> None:
    # Drop in reverse dependency order.
    op.drop_index("ix_agent_traces_agent_started_at", table_name="agent_traces")
    op.drop_index("ix_agent_traces_campaign_id", table_name="agent_traces")
    op.drop_table("agent_traces")
    op.drop_table("regression_runs")
    op.drop_table("patches")
    op.drop_table("vulnerabilities")
    op.drop_table("verdicts")
    op.drop_index("ix_attacks_subcategory_status", table_name="attacks")
    op.drop_index("ix_attacks_campaign_id_status", table_name="attacks")
    op.drop_table("attacks")
    op.drop_table("campaign_briefs")
    op.drop_table("campaigns")
    op.drop_table("target_versions")
    op.drop_table("target_manifests")
    op.drop_table("attack_taxonomy")
    op.execute("DROP EXTENSION IF EXISTS pgcrypto")
