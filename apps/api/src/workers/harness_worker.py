"""Arq job for the regression harness.

The GitHub merge webhook enqueues this job when a patch PR is merged. The
worker resolves the current target_version, replays every confirmed
vulnerability against it via TargetClient + Judge, and writes the
resulting regression_runs rows.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID  # noqa: TC003

from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002

from src.agents.red_team.rate_limit import RateLimiter  # noqa: TC001
from src.agents.red_team.target_client import TargetClient
from src.domain.patch import PatchStatus
from src.domain.regression_run import RegressionOutcome  # noqa: TC001
from src.harness.replay import make_live_replay
from src.harness.runner import FlaggedVulnerability, run_regressions, run_single_vulnerability
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.repositories.patches import PatchRepository
from src.repositories.target_manifests import TargetManifestRepository
from src.repositories.target_versions import TargetVersionRepository
from src.settings import Settings  # noqa: TC001
from src.workers.queue import enqueue_patch_retry_unstable

# Hard cap on patch attempts per vulnerability. Attempt #1 = initial,
# attempt #2 = first (and only) retry. After attempt #2 lands UNSTABLE or
# REGRESSED the vuln waits for a human — see CLAUDE.md "Auto-retry on
# unstable regression".
_MAX_PATCH_ATTEMPTS = 2

# Default replay count per vulnerability. Three samples is the minimum
# that lets aggregate_replays distinguish "regressed" (majority) from
# "unstable" (minority) outcomes without paying for a costly N.
_DEFAULT_REPLAY_COUNT = 3


async def run_regression_sweep(
    ctx: dict[str, Any],
    target_version_hint: str,
    triggered_by: str,
    request_id: str,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    """Arq job: replay all confirmed vulns against the latest target version.

    Args:
        target_version_hint: free-form version string from the webhook
            (e.g. merge_commit_sha). The worker upserts a target_versions
            row keyed on the active target_id from the active manifest.
        triggered_by: how the run was kicked off ("github_merge" |
            "operator_manual"). Recorded on every regression_runs row.
    """
    set_request_id(request_id)
    log_event(
        "harness_job_started",
        target_version_hint=target_version_hint,
        triggered_by=triggered_by,
        outcome="started",
    )

    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]
    settings: Settings = ctx["settings"]
    rate_limiter: RateLimiter = ctx["rate_limiter"]

    async with session_factory() as session:
        try:
            manifest = await TargetManifestRepository().get_active(session)
            if manifest is None:
                log_event(
                    "harness_job_aborted",
                    reason="no_active_target_manifest",
                    outcome="aborted",
                )
                await session.commit()
                return {"status": "no_target_manifest"}

            version = await TargetVersionRepository().get_or_create_latest(
                session,
                target_manifest_id=manifest.id,
                target_id=manifest.target_id,
                version=target_version_hint or "unknown",
                triggered_by=triggered_by,
                commit_hash=commit_sha,
            )

            target_client = TargetClient(settings, rate_limiter)
            try:
                async with target_client:
                    await target_client.authenticate()
                    replay_fn = make_live_replay(
                        session=session,
                        target_client=target_client,
                        llm_client=llm_client,
                    )
                    summary = await run_regressions(
                        session=session,
                        target_version_id=version.id,
                        replay_count=_DEFAULT_REPLAY_COUNT,
                        replay_fn=replay_fn,
                        triggered_by=triggered_by,
                    )
            except Exception:
                await session.rollback()
                raise

            # Auto-retry decision: any vuln flipped to UNSTABLE or REGRESSED
            # by this sweep may need a 2nd-attempt patch. Same transaction
            # as the sweep so the SUPERSEDED flip on the prior patch
            # commits atomically with the regression_runs writes.
            try:
                flagged_tuples = [
                    (f.vulnerability_id, f.outcome) for f in summary.flagged_for_retry
                ]
                await process_unstable_retries(
                    session=session,
                    flagged=flagged_tuples,
                    request_id=request_id,
                )
            except Exception:
                await session.rollback()
                raise

            await session.commit()
        except Exception:
            log_event(
                "harness_job_failed",
                outcome="failure",
            )
            raise

    log_event(
        "harness_job_finished",
        target_version_id=str(summary.target_version_id),
        swept_count=summary.swept_count,
        fix_verified_count=summary.fix_verified_count,
        regressed_count=summary.regressed_count,
        unstable_count=summary.unstable_count,
        target_unavailable_count=summary.target_unavailable_count,
        outcome="success",
    )

    return {
        "target_version_id": str(summary.target_version_id),
        "swept_count": summary.swept_count,
        "fix_verified_count": summary.fix_verified_count,
        "regressed_count": summary.regressed_count,
        "unstable_count": summary.unstable_count,
        "target_unavailable_count": summary.target_unavailable_count,
    }


async def rerun_single_vulnerability(
    ctx: dict[str, Any],
    vulnerability_id: str,
    triggered_by: str,
    request_id: str,
    replays: int = 1,
) -> dict[str, Any]:
    """Arq job: replay one vulnerability against the current target version.

    Operator-facing counterpart of run_regression_sweep. Triggered by the
    "Re-run this attack" button on the vulnerability detail page. Writes a
    single regression_runs row (triggered_by='operator_rerun:{vuln_id}') and
    flips vulnerabilities.status using the same rules as the sweep.

    Idempotency (CLAUDE.md §5): the route assigns _job_id keyed on
    rerun:{vuln_id}:{epoch_minute}, so repeat clicks within a 60-second
    window collapse to a single arq job.
    """
    from uuid import UUID

    set_request_id(request_id)
    log_event(
        "harness_rerun_started",
        vulnerability_id=vulnerability_id,
        replays=replays,
        triggered_by=triggered_by,
        outcome="started",
    )

    if replays < 1 or replays > 5:
        raise ValueError("replays must be in [1, 5]")

    vuln_uuid = UUID(vulnerability_id)

    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]
    settings: Settings = ctx["settings"]
    rate_limiter: RateLimiter = ctx["rate_limiter"]

    async with session_factory() as session:
        try:
            manifest = await TargetManifestRepository().get_active(session)
            if manifest is None:
                log_event(
                    "harness_rerun_aborted",
                    reason="no_active_target_manifest",
                    outcome="aborted",
                )
                await session.commit()
                return {"status": "no_target_manifest"}

            version = await TargetVersionRepository().get_or_create_latest(
                session,
                target_manifest_id=manifest.id,
                target_id=manifest.target_id,
                version="operator_rerun",
                triggered_by=triggered_by,
                commit_hash=None,
            )

            target_client = TargetClient(settings, rate_limiter)
            try:
                async with target_client:
                    await target_client.authenticate()
                    replay_fn = make_live_replay(
                        session=session,
                        target_client=target_client,
                        llm_client=llm_client,
                    )
                    rerun = await run_single_vulnerability(
                        session=session,
                        vulnerability_id=vuln_uuid,
                        target_version_id=version.id,
                        replay_count=replays,
                        replay_fn=replay_fn,
                        triggered_by=triggered_by,
                    )
            except Exception:
                await session.rollback()
                raise

            await session.commit()
        except Exception:
            log_event(
                "harness_rerun_failed",
                vulnerability_id=vulnerability_id,
                outcome="failure",
            )
            raise

    log_event(
        "harness_rerun_finished_job",
        vulnerability_id=vulnerability_id,
        outcome=rerun.outcome.value,
        prior_status=rerun.prior_status,
        new_status=rerun.new_status,
    )
    return {
        "vulnerability_id": vulnerability_id,
        "regression_run_id": (
            str(rerun.regression_run_id) if rerun.regression_run_id is not None else None
        ),
        "outcome": rerun.outcome.value,
        "prior_status": rerun.prior_status,
        "new_status": rerun.new_status,
    }


async def process_unstable_retries(
    *,
    session: AsyncSession,
    flagged: list[tuple[UUID, RegressionOutcome]],
    request_id: str,
) -> None:
    """For each vuln transitioned to UNSTABLE/REGRESSED, decide auto-retry.

    Rules (CLAUDE.md "Auto-retry on unstable regression"):
      - Look up the vuln's current active patch (status in
        awaiting_human_review / merged) and read attempt_number.
      - If attempt_number < 2: enqueue patch.retry_unstable and flip the
        prior patch to SUPERSEDED in this transaction. The new attempt's
        status will be inserted by the retry worker.
      - If attempt_number >= 2: log structured event
        patch_retry_exhausted with {vulnerability_id, attempt_number,
        outcome}. The vuln stays in UNSTABLE/REGRESSED and waits for a
        human.

    This function is intentionally synchronous-feeling (no I/O in the
    decision path — patch lookup + status flip + enqueue are sequential).
    It runs inside the harness sweep's transaction so the SUPERSEDED flip
    on attempt #1 commits atomically with the regression_runs writes.
    """
    if not flagged:
        return

    patch_repo = PatchRepository()
    for vuln_id, outcome in flagged:
        prior_patch = await patch_repo.get_by_vulnerability_id(session, vuln_id)
        if prior_patch is None:
            # No active patch (status in awaiting_human_review/merged).
            # This is unusual — the regression sweep targets vulns that
            # had a fix proposed — but if it happens we skip the retry
            # rather than crash.
            log_event(
                "patch_retry_skip_no_active_patch",
                vulnerability_id=str(vuln_id),
                outcome=outcome.value,
            )
            continue

        if prior_patch.attempt_number >= _MAX_PATCH_ATTEMPTS:
            # Cap reached. The vuln needs a human.
            log_event(
                "patch_retry_exhausted",
                vulnerability_id=str(vuln_id),
                attempt_number=prior_patch.attempt_number,
                outcome=outcome.value,
            )
            continue

        # Flip the prior patch to SUPERSEDED inside this transaction. The
        # retry worker re-asserts this defensively too (idempotent).
        await patch_repo.update_status(
            session,
            patch_id=prior_patch.id,
            new_status=PatchStatus.SUPERSEDED,
        )

        await enqueue_patch_retry_unstable(vuln_id, request_id)

        log_event(
            "patch_retry_enqueued",
            vulnerability_id=str(vuln_id),
            prior_patch_id=str(prior_patch.id),
            attempt_number=prior_patch.attempt_number,
            outcome=outcome.value,
        )


# Keep a reference to FlaggedVulnerability so external callers (tests,
# documentation) can import it from a single place.
__all__ = [
    "FlaggedVulnerability",
    "process_unstable_retries",
    "rerun_single_vulnerability",
    "run_regression_sweep",
]
