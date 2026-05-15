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
    vulnerability_id: str | UUID,
    request_id: str,
) -> dict[str, Any]:
    """Arq job: open a GitHub PR proposing a fix for the vulnerability."""
    set_request_id(request_id)

    # Older enqueues (pre-helper) pickled the id as UUID rather than str.
    # arq retries those jobs forever otherwise — accept either shape.
    vuln_uuid = vulnerability_id if isinstance(vulnerability_id, UUID) else UUID(vulnerability_id)

    log_event(
        "patch_job_started",
        vulnerability_id=str(vuln_uuid),
        outcome="started",
    )
    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]
    settings: Settings = ctx["settings"]

    if settings.github_pat is None or settings.github_fork_repo is None:
        log_event(
            "patch_job_skipped",
            vulnerability_id=str(vuln_uuid),
            reason="missing_github_config",
            outcome="skipped",
        )
        return {
            "vulnerability_id": str(vuln_uuid),
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
        "vulnerability_id": str(vuln_uuid),
        "patch_id": str(outcome.patch_id) if outcome.patch_id else None,
        "branch_name": outcome.branch_name,
        "pr_url": outcome.pr_url,
        "skipped_reason": outcome.skipped_reason,
    }

    log_event(
        "patch_job_finished",
        vulnerability_id=str(vuln_uuid),
        patch_id=result["patch_id"],
        pr_url=result["pr_url"],
        skipped_reason=outcome.skipped_reason,
        outcome="success" if outcome.skipped_reason is None else "skipped",
    )

    return result
