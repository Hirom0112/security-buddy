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


async def enqueue_orchestrator_tick(campaign_id: UUID, request_id: str) -> None:
    """Push an orchestrator.tick job onto the arq Redis queue.

    Slice 3: called by POST /api/v1/campaigns/start and by the GitHub merge
    webhook once Slice 6's regression worker is in place. _job_id is set to
    f"orchestrator:{campaign_id}" so concurrent ticks for the same campaign
    collapse to a single job (defence-in-depth on top of run_tick's
    idempotency check).
    """
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "orchestrator_tick",
            str(campaign_id),
            request_id,
            _job_id=f"orchestrator:{campaign_id}",
        )
    finally:
        await redis.close()


async def enqueue_documentation_write(verdict_id: UUID, request_id: str) -> None:
    """Push a documentation.write job onto the arq Redis queue.

    Slice 4 handoff: the Judge worker enqueues this whenever a verdict row
    is written with verdict='exploit'. _job_id is f"doc:{verdict_id}" so
    concurrent enqueues for the same verdict collapse to a single job
    (defence on top of run_document's existing-vuln short-circuit).
    """
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "write_documentation",
            str(verdict_id),
            request_id,
            _job_id=f"doc:{verdict_id}",
        )
    finally:
        await redis.close()


async def enqueue_harness_regression_sweep(
    target_version_hint: str,
    triggered_by: str,
    request_id: str,
    commit_sha: str | None = None,
) -> None:
    """Push a harness.run_regression_sweep job onto the arq Redis queue.

    Slice 6 handoff: the GitHub merge webhook enqueues this whenever a
    Patch-Agent PR is merged. Coalesces concurrent sweeps for the same
    target_version_hint via _job_id.
    """
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "run_regression_sweep",
            target_version_hint,
            triggered_by,
            request_id,
            commit_sha,
            _job_id=f"harness:{target_version_hint}",
        )
    finally:
        await redis.close()


async def enqueue_rerun_single_vulnerability(
    vulnerability_id: UUID,
    request_id: str,
    *,
    replays: int = 1,
    bucket_epoch_seconds: int,
) -> str:
    """Push a harness.rerun_single_vulnerability job onto the arq Redis queue.

    Idempotency: `_job_id = f"rerun:{vulnerability_id}:{bucket_epoch_seconds}"`
    where the bucket is `int(time.time()) // 60` (a one-minute window). Two
    operator clicks on the "Re-run this attack" button within the same window
    collapse to a single arq job.

    Returns the chosen arq job_id so the route can echo it back to the UI
    (useful for polling diagnostics).
    """
    job_id = f"rerun:{vulnerability_id}:{bucket_epoch_seconds}"
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "rerun_single_vulnerability",
            str(vulnerability_id),
            f"operator_rerun:{vulnerability_id}",
            request_id,
            replays,
            _job_id=job_id,
        )
    finally:
        await redis.close()
    return job_id


async def enqueue_patch_retry_unstable(vulnerability_id: UUID, request_id: str) -> None:
    """Push a patch.retry_unstable job onto the arq Redis queue.

    Auto-retry handoff: the harness worker enqueues this whenever a
    regression sweep flips a vulnerability to UNSTABLE or REGRESSED while
    attempt_number<2. _job_id is f"patch_retry:{vulnerability_id}" so
    duplicate sweeps collapse to a single retry (defence on top of the
    partial unique index on (vulnerability_id, attempt_number)).
    """
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "retry_unstable_patch",
            str(vulnerability_id),
            request_id,
            _job_id=f"patch_retry:{vulnerability_id}",
        )
    finally:
        await redis.close()


async def enqueue_patch_propose(vulnerability_id: UUID, request_id: str) -> None:
    """Push a patch.propose job onto the arq Redis queue.

    Slice 5 handoff: the Documentation worker enqueues this whenever a
    non-critical vulnerabilities row lands in status='open'. _job_id is
    f"patch:{vulnerability_id}" so concurrent enqueues collapse (defence
    on top of run_propose's existing-patch short-circuit + the partial
    unique index on patches.vulnerability_id).
    """
    settings = get_settings()
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    try:
        await redis.enqueue_job(
            "propose_patch",
            str(vulnerability_id),
            request_id,
            _job_id=f"patch:{vulnerability_id}",
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
