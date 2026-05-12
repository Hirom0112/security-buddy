"""Arq worker for the Red Team execution job.

Handles the 'execute_red_team' function, which the arq job runner calls.
Also defines WorkerSettings consumed by:
    arq src.workers.red_team_worker.WorkerSettings

Idempotency (CLAUDE.md §5):
  - max_tries=3: arq will retry on crash up to 3 times.
  - keep_result=300: completed job IDs persist for 5 minutes (duplicate
    job deduplication window).
  - run_executor() checks brief.status == 'completed' and returns early if
    already done. Retries after a crash are safe.

Request-ID propagation:
  The request_id passed by the route is restored into the ContextVar at the
  top of the job function so all downstream log_event() calls carry the
  same correlation ID as the originating HTTP request.

Security (CLAUDE.md §2, §4):
  - No shell access, no subprocess.
  - Settings are injected; no hardcoded secrets.
  - Outbound rate limiting is enforced inside run_executor() via TargetClient.
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from arq.connections import RedisSettings
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.agents.red_team.executor import run_executor
from src.agents.red_team.rate_limit import RateLimiter
from src.llm_client.client import LLMClient
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.settings import get_settings
from src.workers.documentation_worker import write_documentation
from src.workers.judge_worker import evaluate_attack
from src.workers.orchestrator_worker import orchestrator_tick
from src.workers.queue import enqueue_judge_evaluate

logger = logging.getLogger("security_buddy.workers")


# ---------------------------------------------------------------------------
# Job function
# ---------------------------------------------------------------------------


async def execute_red_team(ctx: dict[str, Any], brief_id: str, request_id: str) -> dict[str, Any]:
    """Arq job: run the Red Team execution loop for a single campaign brief.

    Args:
        ctx: arq worker context dict (contains 'session_factory', 'rate_limiter').
        brief_id: UUID string of the campaign_brief to execute.
        request_id: Correlation request_id from the originating HTTP request.

    Returns:
        Result dict with 'completed_attack_count' and 'halted_reason'.
    """
    # Restore the request_id ContextVar so all log events in this job are
    # correlated with the originating HTTP request (CLAUDE.md §"Observability").
    set_request_id(request_id)

    log_event(
        "red_team_job_started",
        brief_id=brief_id,
        outcome="started",
    )

    from uuid import UUID

    brief_uuid = UUID(brief_id)

    session_factory: async_sessionmaker[AsyncSession] = ctx["session_factory"]
    rate_limiter: RateLimiter = ctx["rate_limiter"]
    settings = get_settings()

    result = await run_executor(
        brief_id=brief_uuid,
        session_factory=session_factory,
        settings=settings,
        rate_limiter=rate_limiter,
    )

    # Slice 2 handoff: fan out one judge.evaluate job per attack that landed
    # in awaiting_judgment. Done here (not inside the executor) to keep
    # agents/red_team a leaf with no dependency on src.workers.
    awaiting_ids = result.get("awaiting_judgment_attack_ids") or []
    enqueued_judge_jobs = 0
    if isinstance(awaiting_ids, list):
        for raw_id in awaiting_ids:
            if not isinstance(raw_id, str):
                continue
            await enqueue_judge_evaluate(UUID(raw_id), request_id)
            enqueued_judge_jobs += 1

    log_event(
        "red_team_job_finished",
        brief_id=brief_id,
        completed_attack_count=result.get("completed_attack_count"),
        halted_reason=result.get("halted_reason"),
        enqueued_judge_jobs=enqueued_judge_jobs,
        outcome="success",
    )

    return result


# ---------------------------------------------------------------------------
# Worker lifecycle hooks
# ---------------------------------------------------------------------------


async def startup(ctx: dict[str, Any]) -> None:
    """Initialise shared resources once per worker process."""
    settings = get_settings()

    engine = create_async_engine(
        settings.database_url.get_secret_value(), pool_size=5, max_overflow=10
    )
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    rate_limiter = RateLimiter()
    llm_client = LLMClient(settings)

    ctx["engine"] = engine
    ctx["session_factory"] = factory
    ctx["rate_limiter"] = rate_limiter
    ctx["llm_client"] = llm_client

    log_event("red_team_worker_startup", outcome="success")


async def shutdown(ctx: dict[str, Any]) -> None:
    """Clean up shared resources on graceful shutdown."""
    engine = ctx.get("engine")
    if engine is not None:
        await engine.dispose()
    log_event("red_team_worker_shutdown", outcome="success")


# ---------------------------------------------------------------------------
# arq WorkerSettings
# ---------------------------------------------------------------------------


class WorkerSettings:
    """arq worker configuration consumed by: arq src.workers.red_team_worker.WorkerSettings"""

    # evaluate_attack overrides max_tries to 1 at job-call time (set via
    # _max_tries in queue.py is also possible, but we keep this single-process
    # WorkerSettings simple — the Judge job is idempotent at the run_judge
    # layer regardless, so a retry would no-op).
    functions: ClassVar[list[Any]] = [
        execute_red_team,
        evaluate_attack,
        orchestrator_tick,
        write_documentation,
    ]
    max_tries: ClassVar[int] = 3
    keep_result: ClassVar[int] = 300  # 5-minute job deduplication window
    on_startup: ClassVar[Any] = startup
    on_shutdown: ClassVar[Any] = shutdown
    redis_settings: ClassVar[Any] = RedisSettings.from_dsn(get_settings().redis_url)
