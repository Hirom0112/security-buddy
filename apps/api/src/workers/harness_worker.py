"""Arq job for the regression harness.

The GitHub merge webhook enqueues this job when a patch PR is merged. The
worker resolves the current target_version, replays every confirmed
vulnerability against it via TargetClient + Judge, and writes the
resulting regression_runs rows.
"""

from __future__ import annotations

from typing import Any

from src.agents.red_team.rate_limit import RateLimiter  # noqa: TC001
from src.agents.red_team.target_client import TargetClient
from src.harness.replay import make_live_replay
from src.harness.runner import run_regressions, run_single_vulnerability
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.repositories.target_manifests import TargetManifestRepository
from src.repositories.target_versions import TargetVersionRepository
from src.settings import Settings  # noqa: TC001

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
