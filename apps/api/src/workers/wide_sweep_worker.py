"""Arq job for the Wide Sweep campaign mode.

Fires N campaigns back-to-back, each pinned to a different subcategory.
The operator covers a breadth slice of the attack surface in one click.

Idempotency (CLAUDE.md §5):
  Job id is f"wide_sweep:{ts_minute}" so repeated submits within the same
  minute collapse to a single arq job. The per-campaign create + enqueue
  loop is sequential — if the worker crashes mid-loop, arq retries from
  the top; campaigns already created in the previous attempt remain (no
  rollback), but the next sweep run will create fresh campaigns. This is
  acceptable for a manually-triggered operator action and matches the
  existing "every step is idempotent" pattern: re-running yields more
  attack data, not corrupted state.

Architectural notes (CLAUDE.md §"Architectural Boundaries"):
  workers/ is the integration layer; it imports broadly. We call the
  repository directly (same path /campaigns/start uses for the no-pin
  case) and enqueue the orchestrator tick via workers.queue. We do NOT
  HTTP-loop back into the API.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

from src.domain.campaign import CampaignMode
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.repositories.campaigns import CampaignRepository
from src.workers.queue import enqueue_orchestrator_tick


async def run_wide_sweep(
    ctx: dict[str, Any],
    subcategories: list[str],
    budget_per_campaign_usd: str,
    variant_count: int,
    stagger_seconds: int,
    request_id: str,
) -> dict[str, Any]:
    """Iterate the subcategory list, creating one campaign per entry.

    Each campaign is pinned to its subcategory and enqueued for the
    Orchestrator (which in turn enqueues the Red Team executor).
    Between campaigns we sleep ``stagger_seconds`` of real wall-clock
    time so the operator can halt mid-sweep from the UI and so the
    OpenRouter rate limiter has room to breathe.

    Args:
        ctx: arq worker context. Must contain ``session_factory``.
        subcategories: Resolved subcategory list (caller validates).
        budget_per_campaign_usd: Per-campaign budget as a Decimal-compatible
            string. The repository accepts strings; we re-wrap as Decimal
            here so the type is unambiguous server-side.
        variant_count: Variant count per campaign (1..50).
        stagger_seconds: Wall-clock sleep between campaigns (0..300).
        request_id: Originating request_id for log correlation.

    Returns:
        Result dict with ``campaign_ids`` and ``subcategory_count``.
    """
    set_request_id(request_id)

    budget = Decimal(budget_per_campaign_usd)
    log_event(
        "wide_sweep_started",
        subcategory_count=len(subcategories),
        budget_per_campaign_usd=float(budget),
        budget_total_usd=float(budget * len(subcategories)),
        variant_count=variant_count,
        stagger_seconds=stagger_seconds,
        outcome="started",
    )

    session_factory: async_sessionmaker[AsyncSession] = ctx["session_factory"]
    repo = CampaignRepository()
    created_ids: list[str] = []

    for index, subcategory in enumerate(subcategories):
        async with session_factory() as session:
            campaign = await repo.create(
                session,
                target_subcategory=subcategory,
                budget_usd=budget,
                mode=CampaignMode.LIVE,
            )
            await session.commit()

        await enqueue_orchestrator_tick(campaign.id, request_id)
        created_ids.append(str(campaign.id))

        log_event(
            "wide_sweep_campaign_enqueued",
            campaign_id=str(campaign.id),
            subcategory=subcategory,
            index=index,
            total=len(subcategories),
            outcome="enqueued",
        )

        # Real wall-clock sleep — gives the operator time to halt the sweep
        # from the UI and keeps us well below OpenRouter rate limits. We
        # skip the sleep after the last campaign.
        if stagger_seconds > 0 and index < len(subcategories) - 1:
            await asyncio.sleep(stagger_seconds)

    log_event(
        "wide_sweep_completed",
        subcategory_count=len(subcategories),
        campaign_ids=",".join(created_ids),
        outcome="success",
    )

    return {
        "subcategory_count": len(subcategories),
        "campaign_ids": created_ids,
    }
