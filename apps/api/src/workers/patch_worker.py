"""Arq job for the Patch Agent.

Co-located with the other agent workers. The Documentation worker enqueues
this job whenever it writes a non-critical vulnerability with status='open'.
Critical-severity drafts are gated until the operator flips them.

Idempotency (CLAUDE.md §5):
  run_propose() short-circuits when a patch already exists for the
  vulnerability; arq dedup keyed on vulnerability_id is a second line.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from src.agents.patch.github_client import GitHubClient
from src.agents.patch.propose import run_propose
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.settings import Settings  # noqa: TC001


async def propose_patch(
    ctx: dict[str, Any],
    vulnerability_id: str,
    request_id: str,
) -> dict[str, Any]:
    """Arq job: open a GitHub PR proposing a fix for the vulnerability."""
    set_request_id(request_id)

    log_event(
        "patch_job_started",
        vulnerability_id=vulnerability_id,
        outcome="started",
    )

    vuln_uuid = UUID(vulnerability_id)
    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]
    settings: Settings = ctx["settings"]

    if settings.github_pat is None or settings.github_fork_repo is None:
        log_event(
            "patch_job_skipped",
            vulnerability_id=vulnerability_id,
            reason="missing_github_config",
            outcome="skipped",
        )
        return {
            "vulnerability_id": vulnerability_id,
            "patch_id": None,
            "skipped_reason": "missing_github_config",
        }

    github = GitHubClient(
        token=settings.github_pat.get_secret_value(),
        repo=settings.github_fork_repo,
        default_branch=settings.github_default_branch,
    )

    async with session_factory() as session:
        outcome = await run_propose(
            vulnerability_id=vuln_uuid,
            session=session,
            llm_client=llm_client,
            github=github,
        )
        await session.commit()

    result = {
        "vulnerability_id": vulnerability_id,
        "patch_id": str(outcome.patch_id) if outcome.patch_id else None,
        "branch_name": outcome.branch_name,
        "pr_url": outcome.pr_url,
        "skipped_reason": outcome.skipped_reason,
    }

    log_event(
        "patch_job_finished",
        vulnerability_id=vulnerability_id,
        patch_id=result["patch_id"],
        pr_url=result["pr_url"],
        skipped_reason=outcome.skipped_reason,
        outcome="success" if outcome.skipped_reason is None else "skipped",
    )

    return result
