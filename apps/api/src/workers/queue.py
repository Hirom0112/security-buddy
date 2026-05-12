"""Arq job-enqueue helpers.

Routes call these helpers to push jobs onto the Redis queue.
This module is the ONLY arq surface that routes may import — keeping routes/
free of direct arq dependencies satisfies the import-linter contract.

Request-ID propagation (CLAUDE.md §"Observability"):
  The FastAPI route reads the current request_id ContextVar and passes it in
  the job payload. The worker restores it via set_request_id() before doing
  any work. This maintains the correlation thread across the async boundary.
"""

from __future__ import annotations

from uuid import UUID  # noqa: TC003

from arq import create_pool
from arq.connections import RedisSettings

from src.settings import get_settings


async def enqueue_red_team_execute(brief_id: UUID, request_id: str) -> None:
    """Push a red_team.execute job onto the arq Redis queue.

    Opens a fresh arq connection pool per call (low-frequency operation — no
    persistent connection needed in the route layer).

    Args:
        brief_id: UUID of the campaign_brief to process.
        request_id: Current request_id from the RequestIdMiddleware ContextVar.
            Passed through so the worker can restore it before processing.
    """
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "execute_red_team",
            str(brief_id),
            request_id,
        )
    finally:
        await redis.close()


async def enqueue_judge_evaluate(attack_id: UUID, request_id: str) -> None:
    """Push a judge.evaluate job onto the arq Redis queue.

    Slice 2 handoff: the Red Team executor enqueues one of these per attack
    transitioned to awaiting_judgment. The Judge worker picks them up, calls
    the LLM, writes a verdict, and flips the attack to judged.

    The arq job's _job_id is set to f"judge:{attack_id}" so concurrent
    enqueues for the same attack collapse to a single job (an extra defense
    against double-judging on top of the DB unique constraint).
    """
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "evaluate_attack",
            str(attack_id),
            request_id,
            _job_id=f"judge:{attack_id}",
        )
    finally:
        await redis.close()
