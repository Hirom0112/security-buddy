"""Orchestrator tick — one strategic decision per call.

Flow:
  1. Load CoverageRows for the current target_version_id.
  2. Score them with the deterministic priority function.
  3. If no candidates, mark the campaign no_candidates and return.
  4. Resolve the chosen subcategory's manifest fragment.
  5. Call the brief generator (LLM, with fallback) to frame the campaign.
  6. Clamp the LLM's variant/budget proposals against the worker's caps.
  7. Update the campaign + brief rows in Postgres.
  8. Return a structured TickOutcome the worker uses for follow-up enqueues.

The Orchestrator does NOT enqueue the Red Team. The worker layer does
(import-linter: agents/orchestrator cannot depend on src.workers).

Idempotency: a campaign with status != pending is treated as already
processed; re-running the tick on it short-circuits. The unique brief per
campaign is enforced by callers selecting an empty campaign.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from uuid import UUID  # noqa: TC003

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002

from src.agents.orchestrator import budget_enforcer
from src.agents.orchestrator.brief_generator import generate_brief
from src.agents.orchestrator.priority import pick_top, rank_subcategories
from src.domain.campaign import CampaignStatus
from src.domain.coverage import CoverageRow, PriorityScore  # noqa: TC001
from src.domain.errors import NotFoundError
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.events import log_event
from src.repositories.agent_traces import AgentTracesRepository
from src.repositories.campaigns import CampaignRepository
from src.repositories.coverage import CoverageRepository
from src.repositories.target_manifests import TargetManifestRepository

# Hard caps on what the LLM can propose. CLAUDE.md §"Cost discipline":
# the LLM may suggest values; the worker enforces them in code.
_MAX_VARIANT_COUNT: int = 50
_MAX_BUDGET_USD: Decimal = Decimal("10.00")


async def _subcategory_in_taxonomy(session: AsyncSession, subcategory: str) -> bool:
    """Return True if the subcategory exists in attack_taxonomy.

    Mirrors `routes.campaigns._subcategory_exists` but kept local to the tick
    module so the agents/orchestrator package does not import from routes/.
    """
    result = await session.execute(
        sa.text("SELECT 1 FROM attack_taxonomy WHERE subcategory = :sub LIMIT 1"),
        {"sub": subcategory},
    )
    return result.first() is not None


def _priority_for_pin(subcategory: str, rows: list[CoverageRow]) -> PriorityScore | None:
    """Return the PriorityScore the priority function would assign to `subcategory`.

    Used when an operator pin bypasses pick_top(): we still want the same
    breakdown attached to the TickOutcome and brief so the UI shows a real
    score, just for a possibly-not-top row.
    """
    for score in rank_subcategories(rows):
        if score.subcategory == subcategory:
            return score
    return None


@dataclass(frozen=True)
class TickOutcome:
    """Returned by run_tick — caller (worker) decides whether to enqueue."""

    campaign_id: UUID
    chosen_subcategory: str | None
    brief_id: UUID | None
    used_fallback: bool
    halted_reason: str | None
    priority_breakdown: dict[str, float] | None


async def run_tick(
    *,
    campaign_id: UUID,
    session: AsyncSession,
    llm_client: LLMClient,
) -> TickOutcome:
    """Run one Orchestrator decision cycle for an empty pending campaign."""
    campaign_repo = CampaignRepository()
    coverage_repo = CoverageRepository()
    manifest_repo = TargetManifestRepository()
    traces_repo = AgentTracesRepository()

    campaign = await campaign_repo.get(session, campaign_id)
    if campaign is None:
        raise NotFoundError(f"Campaign {campaign_id} not found")

    # ------------------------------------------------------------------
    # Idempotency: anything past pending has already been ticked.
    # ------------------------------------------------------------------
    if campaign.status != CampaignStatus.PENDING:
        log_event(
            "orchestrator_tick_skip",
            campaign_id=str(campaign_id),
            outcome="already_processed",
            status=campaign.status.value,
        )
        return TickOutcome(
            campaign_id=campaign_id,
            chosen_subcategory=campaign.target_subcategory,
            brief_id=None,
            used_fallback=False,
            halted_reason="already_processed",
            priority_breakdown=None,
        )

    # ------------------------------------------------------------------
    # Pre-flight budget check. A campaign starts with budget; an operator
    # who set it to zero or below gets no work done.
    # ------------------------------------------------------------------
    spent = await traces_repo.total_cost_for_campaign(session, campaign_id)
    decision = budget_enforcer.evaluate(spent_usd=spent, budget_usd=campaign.budget_usd)
    if decision.should_halt:
        await campaign_repo.update_status(
            session,
            campaign_id=campaign_id,
            status=CampaignStatus.BUDGET_EXHAUSTED,
            expected_version_id=campaign.version_id,
        )
        log_event(
            "orchestrator_tick_halt",
            campaign_id=str(campaign_id),
            outcome="budget_exhausted_at_start",
            fraction=decision.fraction,
        )
        return TickOutcome(
            campaign_id=campaign_id,
            chosen_subcategory=None,
            brief_id=None,
            used_fallback=False,
            halted_reason="budget_exhausted",
            priority_breakdown=None,
        )

    # ------------------------------------------------------------------
    # Layer A — deterministic priority math.
    #
    # If the operator pinned a `target_subcategory` on the campaign
    # (POST /api/v1/campaigns/start with the optional override), that
    # pin is authoritative: we skip pick_top() entirely after validating
    # the pin against attack_taxonomy. An invalid pin falls back to the
    # priority pick so the loop keeps moving rather than dead-ending on
    # operator error. Both branches emit a structured log line so the
    # decision is auditable.
    # ------------------------------------------------------------------
    rows: list[CoverageRow] = await coverage_repo.snapshot(
        session, target_version_id=campaign.target_version_id
    )

    top: PriorityScore | None = None
    pin = campaign.target_subcategory
    if pin is not None:
        pin_known = await _subcategory_in_taxonomy(session, pin)
        if pin_known:
            top = _priority_for_pin(pin, rows)
            log_event(
                "orchestrator_pin_override",
                campaign_id=str(campaign_id),
                subcategory=pin,
                priority_score=round(top.score, 4) if top is not None else None,
                outcome="pin_honoured",
            )
        else:
            log_event(
                "orchestrator_pin_invalid",
                campaign_id=str(campaign_id),
                subcategory=pin,
                outcome="pin_rejected_fallback_to_priority",
            )

    if top is None:
        top = pick_top(rows)

    if top is None:
        await campaign_repo.update_status(
            session,
            campaign_id=campaign_id,
            status=CampaignStatus.NO_CANDIDATES,
            expected_version_id=campaign.version_id,
        )
        log_event(
            "orchestrator_tick_no_candidates",
            campaign_id=str(campaign_id),
            outcome="no_candidates",
        )
        return TickOutcome(
            campaign_id=campaign_id,
            chosen_subcategory=None,
            brief_id=None,
            used_fallback=False,
            halted_reason="no_candidates",
            priority_breakdown=None,
        )

    chosen_row = next(r for r in rows if r.subcategory == top.subcategory)

    # ------------------------------------------------------------------
    # Layer B — LLM brief framing (with deterministic fallback).
    # ------------------------------------------------------------------
    manifest = await manifest_repo.get_active(session)
    manifest_fragment: dict[str, Any] = {}
    if manifest is not None:
        behaviors = manifest.manifest_json.get("expected_safe_behaviors_by_subcategory", {})
        manifest_fragment = {
            "expected_safe_behavior": behaviors.get(top.subcategory),
            "primary_attack_endpoint": manifest.manifest_json.get("primary_attack_endpoint"),
        }

    brief, used_fallback = await generate_brief(
        priority=top,
        row=chosen_row,
        manifest_fragment=manifest_fragment,
        llm_client=llm_client,
        campaign_id=campaign_id,
    )

    # ------------------------------------------------------------------
    # Clamp the LLM's proposals against the worker's hard caps.
    # CLAUDE.md §"Cost discipline": the worker enforces, not the prompt.
    # ------------------------------------------------------------------
    variant_count = min(brief.proposed_variant_count, _MAX_VARIANT_COUNT)
    proposed_budget = min(brief.proposed_budget_usd, _MAX_BUDGET_USD)
    final_budget = min(proposed_budget, campaign.budget_usd)

    # ------------------------------------------------------------------
    # Persist the campaign's chosen subcategory + create the brief.
    # Campaign.target_subcategory is nullable in the schema for empty-start
    # campaigns; we set it on tick.
    # ------------------------------------------------------------------
    await campaign_repo.set_target_subcategory(
        session,
        campaign_id=campaign_id,
        target_subcategory=top.subcategory,
        expected_version_id=campaign.version_id,
    )

    success_criteria_serialised: dict[str, Any] = dict(brief.success_criteria)
    brief_row = await campaign_repo.add_brief(
        session,
        campaign_id=campaign_id,
        description=brief.description,
        variant_count=variant_count,
        target_subcategory=top.subcategory,
        success_criteria=success_criteria_serialised,
        budget_usd=final_budget,
    )

    log_event(
        "orchestrator_tick_finished",
        campaign_id=str(campaign_id),
        brief_id=str(brief_row.id),
        subcategory=top.subcategory,
        priority_score=round(top.score, 4),
        used_fallback=used_fallback,
        variant_count=variant_count,
        outcome="success",
    )

    return TickOutcome(
        campaign_id=campaign_id,
        chosen_subcategory=top.subcategory,
        brief_id=brief_row.id,
        used_fallback=used_fallback,
        halted_reason=None,
        priority_breakdown=top.breakdown,
    )
