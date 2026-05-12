"""Arq job function for the Judge agent.

Co-located with the red_team_worker in the same worker process (shared ctx
with session_factory + llm_client). One process, two functions:
  - execute_red_team(brief_id, request_id)
  - evaluate_attack(attack_id, request_id)

CLAUDE.md §"Common Gotchas":
  arq default max_tries=5. The Judge LLM call costs money; we override to
  max_tries=1 in WorkerSettings (job-level override below). A crashed
  judge job leaves the attack in awaiting_judgment, which is the correct
  recovery state — a separate retry script can re-enqueue if desired,
  but we will not silently double-spend.

Idempotency (CLAUDE.md §5):
  run_judge() short-circuits when a verdict row already exists for the
  attack. So even if the queue dedup misses and a second job fires, the
  second LLM call is skipped.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from arq.constants import default_queue_name as ARQ_DEFAULT_QUEUE_NAME  # noqa: F401 — re-exported

from src.agents.judge.judge import run_judge
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.context import set_request_id
from src.observability.events import log_event


async def evaluate_attack(
    ctx: dict[str, Any],
    attack_id: str,
    request_id: str,
) -> dict[str, Any]:
    """Arq job: adjudicate a single attack.

    Args:
        ctx: arq worker context (contains 'session_factory' and 'llm_client').
        attack_id: UUID string of the attack to judge.
        request_id: Correlation request_id from the originating HTTP request.

    Returns:
        Dict with the resulting verdict id, label, and skipped_reason (None
        when a fresh LLM call was made).
    """
    set_request_id(request_id)

    log_event(
        "judge_job_started",
        attack_id=attack_id,
        outcome="started",
    )

    attack_uuid = UUID(attack_id)
    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]

    async with session_factory() as session:
        outcome = await run_judge(
            attack_id=attack_uuid,
            session=session,
            llm_client=llm_client,
        )
        await session.commit()

    result = {
        "attack_id": attack_id,
        "verdict_id": str(outcome.verdict_id),
        "verdict": outcome.verdict.value,
        "skipped_reason": outcome.skipped_reason,
    }

    log_event(
        "judge_job_finished",
        attack_id=attack_id,
        verdict_id=result["verdict_id"],
        verdict=result["verdict"],
        skipped_reason=outcome.skipped_reason,
        outcome="success",
    )

    return result
