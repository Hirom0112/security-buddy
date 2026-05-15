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
from src.workers.harness_worker import rerun_single_vulnerability, run_regression_sweep
from src.workers.judge_worker import evaluate_attack
from src.workers.orchestrator_worker import orchestrator_tick
from src.workers.patch_retry_worker import retry_unstable_patch
from src.workers.patch_worker import propose_patch
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
    llm_client: LLMClient = ctx["llm_client"]
    settings = get_settings()

    # Per-attack Judge enqueue (TODO #59): pass a callable into the executor
    # rather than batching at the end. If the executor crashes or arq's
    # job_timeout fires mid-run, every attack already in awaiting_judgment
    # has its Judge job sitting in Redis. enqueue_judge_evaluate dedups on
    # _job_id="judge:{attack_id}" so a retried executor that re-fires (it
    # shouldn't, given the AttackStatus gate in run_executor) cannot
    # double-enqueue.
    result = await run_executor(
        brief_id=brief_uuid,
        session_factory=session_factory,
        settings=settings,
        rate_limiter=rate_limiter,
        judge_enqueuer=enqueue_judge_evaluate,
        request_id=request_id,
        llm_client=llm_client,
    )

    awaiting_ids = result.get("awaiting_judgment_attack_ids") or []
    enqueued_judge_jobs = len(awaiting_ids) if isinstance(awaiting_ids, list) else 0

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
    llm_client = LLMClient(settings, session_factory=factory)

    ctx["engine"] = engine
    ctx["session_factory"] = factory
    ctx["rate_limiter"] = rate_limiter
    ctx["llm_client"] = llm_client
    ctx["settings"] = settings

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
        propose_patch,
        retry_unstable_patch,
        run_regression_sweep,
        rerun_single_vulnerability,
    ]
    max_tries: ClassVar[int] = 3
    keep_result: ClassVar[int] = 300  # 5-minute job deduplication window
    # arq default is 300s. A 50-variant Red Team run at ~8s/attack overruns
    # that and the worker raises TimeoutError mid-loop (TODO #59 — observed
    # on live campaign 60662d6c, 2026-05-12). 1800s is the defensive ceiling;
    # the fundamental fix is per-attack Judge enqueue in executor.py so a
    # timeout mid-run no longer strands attacks in awaiting_judgment.
    job_timeout: ClassVar[int] = 1800
    on_startup: ClassVar[Any] = startup
    on_shutdown: ClassVar[Any] = shutdown
    redis_settings: ClassVar[Any] = RedisSettings.from_dsn(get_settings().redis_url)
