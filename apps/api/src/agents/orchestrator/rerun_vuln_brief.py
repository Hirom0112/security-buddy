"""Rerun-vuln brief generator.

Builds a deterministic CampaignBrief seeded with a previously-confirmed
vulnerability's exact attack input. The brief is pinned to the vuln's
subcategory and instructs the Red Team to mutate the seed across all four
mutation strategies (lexical/structural/multi_turn/llm).

This module does not call the LLM — the seed is concrete and the brief is
deterministic. It is invoked from the route handler when an operator picks
"Re-attack regressed vuln" in the Start Campaign modal.

Architectural boundary (import-linter):
  agents/orchestrator may import domain/, repositories/, llm_client/,
  observability/. We use sqlalchemy.text directly for the join — same
  pattern as tick.py — to avoid adding a one-off repository method.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal  # noqa: TC003
from typing import Any
from uuid import UUID  # noqa: TC003

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002

from src.observability.events import log_event

# Marker key embedded in campaign_briefs.success_criteria (jsonb) so the
# Red Team executor's seed-loading step can substitute a custom synthetic
# seed for the loaded library seeds. Kept narrow on purpose: only the
# fields a mutation strategy actually reads.
RERUN_SEED_KEY: str = "__rerun_seed__"

# Default variant count for a rerun-vuln campaign. Operators can override
# via the StartCampaignRequest body; the worker still clamps against its
# global max.
DEFAULT_RERUN_VARIANT_COUNT: int = 20


@dataclass(frozen=True)
class RerunSeedFragment:
    """Concrete fields the executor needs to synthesize a SeedAttack.

    Mirrors a subset of `agents.red_team.types.SeedAttack` — the fields a
    mutation strategy actually reads. We do not import SeedAttack here to
    keep this module independent of the red_team package.
    """

    seed_id: str
    category: str
    subcategory: str
    attack_input: str
    target_endpoint: str
    framework_versions: dict[str, Any]
    vulnerability_id: str
    vuln_label: str  # e.g. 'VUL-0017'


@dataclass(frozen=True)
class RerunBriefDraft:
    """Pure data the route handler persists via CampaignRepository.add_brief."""

    description: str
    variant_count: int
    target_subcategory: str
    success_criteria: dict[str, Any]
    budget_usd: Decimal
    seed: RerunSeedFragment


async def _load_vuln_for_rerun(
    session: AsyncSession,
    vulnerability_id: UUID,
) -> dict[str, Any] | None:
    """Fetch the vuln + its seed attack row in one round-trip.

    Returns None when the vulnerability does not exist; caller maps that to
    404 / 422 as appropriate.
    """
    result = await session.execute(
        sa.text(
            """
            SELECT
              v.id                AS vuln_pk,
              v.vuln_id           AS vuln_label,
              v.status            AS vuln_status,
              v.title             AS vuln_title,
              v.framework_versions AS framework_versions,
              a.attack_input      AS attack_input,
              a.category          AS attack_category,
              a.subcategory       AS attack_subcategory
            FROM vulnerabilities v
            JOIN attacks a ON a.id = v.attack_id
            WHERE v.id = :vid
            LIMIT 1
            """
        ),
        {"vid": str(vulnerability_id)},
    )
    row = result.mappings().first()
    return dict(row) if row else None


def _build_description(vuln_label: str, subcategory: str, vuln_title: str) -> str:
    """Deterministic brief description — no LLM call needed."""
    return (
        f"Re-attack of {vuln_label} ({subcategory}). "
        f"The Red Team will mutate the original exact attack input across "
        f"lexical, structural, multi-turn, and LLM strategies and fire the "
        f"variants against the current target build. "
        f"Original finding: {vuln_title}. "
        f"Success criterion: any Judge verdict of 'exploit' on a mutated "
        f"variant indicates the vulnerability has regressed or is unstable."
    )


async def build_rerun_brief(
    *,
    session: AsyncSession,
    vulnerability_id: UUID,
    budget_usd: Decimal,
    variant_count: int = DEFAULT_RERUN_VARIANT_COUNT,
) -> RerunBriefDraft | None:
    """Given a vulnerability id, return a deterministic brief draft.

    Returns None when the vulnerability cannot be found. The caller is
    responsible for persisting via CampaignRepository.add_brief() and
    enqueueing the Red Team job.
    """
    row = await _load_vuln_for_rerun(session, vulnerability_id)
    if row is None:
        log_event(
            "rerun_vuln_brief_vuln_not_found",
            vulnerability_id=str(vulnerability_id),
            outcome="not_found",
        )
        return None

    subcategory = str(row["attack_subcategory"])
    seed = RerunSeedFragment(
        seed_id=f"rerun-{row['vuln_label']}",
        category=str(row["attack_category"]),
        subcategory=subcategory,
        attack_input=str(row["attack_input"]),
        # The target endpoint is recovered from the seed library at
        # executor-time when the marker key resolves; we record a sentinel
        # here so the persisted seed_used column stays informative.
        target_endpoint="rerun:original",
        framework_versions=dict(row["framework_versions"] or {}),
        vulnerability_id=str(vulnerability_id),
        vuln_label=str(row["vuln_label"]),
    )

    success_criteria: dict[str, Any] = {
        "mode": "rerun_vuln",
        "vulnerability_id": str(vulnerability_id),
        "vuln_label": seed.vuln_label,
        "evidence_required": (
            "Any Judge verdict of 'exploit' on a mutated variant indicates "
            "regression of the rerun vulnerability."
        ),
        # Marker payload consumed by the Red Team executor's seed-loading
        # step (agents/red_team/executor.py). Keeping it inside
        # success_criteria avoids a schema migration on campaign_briefs.
        RERUN_SEED_KEY: {
            "seed_id": seed.seed_id,
            "category": seed.category,
            "subcategory": seed.subcategory,
            "attack_input": seed.attack_input,
            "vulnerability_id": seed.vulnerability_id,
            "vuln_label": seed.vuln_label,
        },
    }

    log_event(
        "rerun_vuln_brief_built",
        vulnerability_id=str(vulnerability_id),
        vuln_label=seed.vuln_label,
        subcategory=subcategory,
        variant_count=variant_count,
        outcome="success",
    )

    return RerunBriefDraft(
        description=_build_description(seed.vuln_label, subcategory, str(row["vuln_title"])),
        variant_count=variant_count,
        target_subcategory=subcategory,
        success_criteria=success_criteria,
        budget_usd=budget_usd,
        seed=seed,
    )
