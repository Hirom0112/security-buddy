"""Arq job for the Orchestrator's tick.

Co-located with the Red Team + Judge workers (shared session_factory +
llm_client in ctx). The handler runs one tick, then enqueues the Red Team
job against the brief the Orchestrator just produced — keeping the
agents/orchestrator package free of any src.workers dependency.

Idempotency (CLAUDE.md §5):
  run_tick() short-circuits when the campaign is not in status='pending'.
  Even if the queue dedup misses, the second tick is a no-op and the
  Red Team enqueue is skipped.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from src.agents.orchestrator.tick import run_tick
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.workers.queue import enqueue_red_team_execute


async def orchestrator_tick(
    ctx: dict[str, Any],
    campaign_id: str,
    request_id: str,
) -> dict[str, Any]:
    """Arq job: run one orchestrator tick for the given campaign."""
    set_request_id(request_id)

    log_event(
        "orchestrator_job_started",
        campaign_id=campaign_id,
        outcome="started",
    )

    campaign_uuid = UUID(campaign_id)
    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]

    async with session_factory() as session:
        outcome = await run_tick(
            campaign_id=campaign_uuid,
            session=session,
            llm_client=llm_client,
        )
        await session.commit()

    enqueued_red_team = False
    if outcome.brief_id is not None and outcome.halted_reason is None:
        await enqueue_red_team_execute(outcome.brief_id, request_id)
        enqueued_red_team = True

    result = {
        "campaign_id": campaign_id,
        "brief_id": str(outcome.brief_id) if outcome.brief_id else None,
        "chosen_subcategory": outcome.chosen_subcategory,
        "used_fallback": outcome.used_fallback,
        "halted_reason": outcome.halted_reason,
        "enqueued_red_team": enqueued_red_team,
    }

    log_event(
        "orchestrator_job_finished",
        campaign_id=campaign_id,
        brief_id=result["brief_id"],
        chosen_subcategory=outcome.chosen_subcategory,
        used_fallback=outcome.used_fallback,
        halted_reason=outcome.halted_reason,
        enqueued_red_team=enqueued_red_team,
        outcome="success",
    )

    return result
