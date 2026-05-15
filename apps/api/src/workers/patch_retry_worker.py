"""Arq job for the auto-retry on unstable regression branch.

Spec — Auto-retry on unstable regression:
  When the regression sweep flips a vulnerability to UNSTABLE or REGRESSED
  while the active patch is attempt #1, harness_worker enqueues
  `patch.retry_unstable`. This handler:

    1. Reads the most recent unstable/regressed regression_runs row for
       the vulnerability (the one that triggered the retry).
    2. Reads the prior patch (attempt #1, now SUPERSEDED) for its
       branch_name + pr_url.
    3. Builds an augmented user message that includes:
         - the original attack input,
         - the prior patch's PR link + branch (so a reviewer-style LLM has
           a handle on what was tried),
         - the failing replay verdicts (so the LLM sees what payloads
           still got through attempt #1).
    4. Runs the same code-search → diff-generation flow as the initial
       patch propose, but writes the new patches row with
       attempt_number=2.

  Cost note (CLAUDE.md): worst case is 2 patches * 2 Sonnet calls each +
  a second regression sweep (~3 Judge calls) ~= $0.10 per vulnerability.
  Acceptable.

Idempotency (CLAUDE.md §5):
  - arq dedup keyed on f"patch_retry:{vulnerability_id}" (see
    queue.enqueue_patch_retry_unstable).
  - Schema-level backstop is migration 0012's partial unique index on
    (vulnerability_id, attempt_number) — a second insert at attempt #2
    raises before any GitHub side-effect.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import sqlalchemy as sa

from src.agents.patch.github_client import (
    CreatedPullRequest,
    GitHubClient,
    GitHubError,
)
from src.agents.patch.model import (
    PATCH_AGENT_TAG,
    PATCH_LLM_TIMEOUT_SECONDS,
    PATCH_MAX_CANDIDATE_FILES,
    PATCH_MODEL,
)
from src.agents.patch.parse import (
    PatchParseError,
    parse_file_selection,
    parse_patch_draft,
)
from src.agents.patch.prompt import (
    build_file_selection_messages,
    build_patch_draft_messages,
)
from src.agents.patch.propose import _branch_name_for
from src.domain.patch import PatchStatus
from src.llm_client.client import LLMClient  # noqa: TC001
from src.llm_client.types import Message
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.repositories.patches import PatchRepository
from src.repositories.vulnerabilities import VulnerabilityRepository
from src.settings import Settings  # noqa: TC001

# Retry caps at attempt #2 — see CLAUDE.md "Auto-retry on unstable regression".
RETRY_ATTEMPT_NUMBER = 2


def build_retry_prompt_user_text(
    *,
    original_attack_input: str,
    prior_patch_pr_url: str,
    prior_patch_branch_name: str,
    failing_verdict_rows: list[dict[str, Any]],
) -> str:
    """Compose the user-message preamble fed into the attempt-#2 prompt.

    Pure function — testable without DB or LLM. The output is appended in
    front of the standard patch-draft user message so the LLM sees the
    regression evidence before it reasons about the diff.
    """
    # The Watch item from the spec: this MUST include the failing replay
    # verdicts, not the original attack alone. We surface every verdict
    # whose label proves attempt #1 didn't hold (exploit / partial) and
    # carry along unclear rows as informational.
    failing_lines: list[str] = []
    bad_count = 0
    for row in failing_verdict_rows:
        verdict = str(row.get("verdict", "unknown"))
        evidence = str(row.get("evidence", ""))
        status = row.get("target_status_code")
        if verdict in ("exploit", "partial"):
            bad_count += 1
        failing_lines.append(f"- verdict={verdict}; target_status={status}; evidence={evidence}")

    payload_block = "\n".join(failing_lines) if failing_lines else "- (none recorded)"

    return (
        "# Retry context — attempt 2 of 2\n"
        "Attempt 1 was opened as the PR below and a regression sweep proved "
        "it does not hold. Build a stronger patch that addresses the failing "
        "replays without over-fitting (do not block legitimate clinician "
        "queries — the happy-path fixtures still need to pass).\n\n"
        f"**Prior patch:** {prior_patch_pr_url}\n"
        f"**Prior branch:** {prior_patch_branch_name}\n"
        f"**Bad replay count:** {bad_count}\n\n"
        "## Original attack input\n"
        f"```\n{original_attack_input}\n```\n\n"
        "## Replay verdicts that proved attempt 1 insufficient\n"
        f"{payload_block}\n\n"
        "---\n"
    )


async def retry_unstable_patch(
    ctx: dict[str, Any],
    vulnerability_id: str,
    request_id: str,
) -> dict[str, Any]:
    """Arq job: open a 2nd-attempt patch PR informed by the failed replays."""
    set_request_id(request_id)
    log_event(
        "patch_retry_job_started",
        vulnerability_id=vulnerability_id,
        outcome="started",
    )

    vuln_uuid = UUID(vulnerability_id)
    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]
    settings: Settings = ctx["settings"]

    if settings.github_pat is None or settings.github_fork_repo is None:
        log_event(
            "patch_retry_job_skipped",
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
        result = await _run_retry(
            session=session,
            vulnerability_id=vuln_uuid,
            llm_client=llm_client,
            github=github,
        )
        await session.commit()

    log_event(
        "patch_retry_job_finished",
        vulnerability_id=vulnerability_id,
        patch_id=result["patch_id"],
        pr_url=result["pr_url"],
        skipped_reason=result["skipped_reason"],
        outcome="success" if result["skipped_reason"] is None else "skipped",
    )
    return result


async def _run_retry(
    *,
    session: Any,
    vulnerability_id: UUID,
    llm_client: LLMClient,
    github: GitHubClient,
) -> dict[str, Any]:
    vuln_repo = VulnerabilityRepository()
    patch_repo = PatchRepository()

    vuln = await vuln_repo.get_by_id(session, vulnerability_id)
    if vuln is None:
        return {
            "vulnerability_id": str(vulnerability_id),
            "patch_id": None,
            "pr_url": None,
            "branch_name": None,
            "skipped_reason": "vulnerability_not_found",
        }

    # Idempotency: did a prior crash leave attempt #2 already inserted?
    existing_attempt_2 = await patch_repo.get_by_vulnerability_id_and_attempt(
        session, vulnerability_id, RETRY_ATTEMPT_NUMBER
    )
    if existing_attempt_2 is not None:
        return {
            "vulnerability_id": str(vulnerability_id),
            "patch_id": str(existing_attempt_2.id),
            "pr_url": existing_attempt_2.pr_url,
            "branch_name": existing_attempt_2.branch_name,
            "skipped_reason": "already_retried",
        }

    # Look up the prior patch (now SUPERSEDED or still active mid-transition)
    # and the regression_runs row that triggered the retry.
    prior_patch = await _get_latest_patch_any_status(session, vulnerability_id)
    if prior_patch is None:
        return {
            "vulnerability_id": str(vulnerability_id),
            "patch_id": None,
            "pr_url": None,
            "branch_name": None,
            "skipped_reason": "no_prior_patch",
        }

    failing_rows = await _get_latest_unstable_or_regressed_verdicts(session, vulnerability_id)
    attack_input = await _get_attack_input(session, vuln.attack_id)
    if attack_input is None:
        return {
            "vulnerability_id": str(vulnerability_id),
            "patch_id": None,
            "pr_url": None,
            "branch_name": None,
            "skipped_reason": "missing_attack_input",
        }

    retry_preamble = build_retry_prompt_user_text(
        original_attack_input=attack_input,
        prior_patch_pr_url=prior_patch.pr_url,
        prior_patch_branch_name=prior_patch.branch_name,
        failing_verdict_rows=failing_rows,
    )

    # LLM call 1 — code search (same shape as the initial propose flow).
    selection_messages = build_file_selection_messages(
        title=vuln.title,
        clinical_impact=vuln.clinical_impact,
        reproduction_steps=vuln.reproduction_steps,
        observed_behavior=vuln.observed_behavior,
        expected_behavior=vuln.expected_behavior,
        recommended_remediation=vuln.recommended_remediation,
        owasp_llm_id=vuln.owasp_llm_id,
        repo_slug=github.repo,
    )

    try:
        sel_completion = await llm_client.complete(
            model=PATCH_MODEL,
            messages=selection_messages,
            agent=PATCH_AGENT_TAG,
            timeout=PATCH_LLM_TIMEOUT_SECONDS,
            campaign_id=None,
            attack_id=vuln.attack_id,
            verdict_id=vuln.verdict_id,
        )
        selection = parse_file_selection(sel_completion.content)
    except (TimeoutError, PatchParseError) as exc:
        log_event(
            "patch_retry_codesearch_failed",
            vulnerability_id=str(vulnerability_id),
            outcome="failure",
            error_class=type(exc).__name__,
        )
        return {
            "vulnerability_id": str(vulnerability_id),
            "patch_id": None,
            "pr_url": None,
            "branch_name": None,
            "skipped_reason": "llm_failure",
        }

    candidate_paths = selection.file_paths[:PATCH_MAX_CANDIDATE_FILES]

    # LLM call 2 — diff generation, prefixed with the retry preamble so the
    # LLM sees the failing payloads BEFORE it reasons about a new diff.
    draft_messages = build_patch_draft_messages(
        title=vuln.title,
        clinical_impact=vuln.clinical_impact,
        reproduction_steps=vuln.reproduction_steps,
        recommended_remediation=vuln.recommended_remediation,
        owasp_llm_id=vuln.owasp_llm_id,
        mitre_atlas_technique_id=vuln.mitre_atlas_technique_id,
        hipaa_safeguard=vuln.hipaa_safeguard,
        vuln_id=vuln.vuln_id,
        repo_slug=github.repo,
        candidate_paths=candidate_paths,
    )
    draft_messages = [
        *draft_messages[:-1],
        Message(
            role="user",
            content=retry_preamble + draft_messages[-1].content,
        ),
    ]

    try:
        draft_completion = await llm_client.complete(
            model=PATCH_MODEL,
            messages=draft_messages,
            agent=PATCH_AGENT_TAG,
            timeout=PATCH_LLM_TIMEOUT_SECONDS,
            campaign_id=None,
            attack_id=vuln.attack_id,
            verdict_id=vuln.verdict_id,
        )
        draft = parse_patch_draft(draft_completion.content)
    except (TimeoutError, PatchParseError) as exc:
        log_event(
            "patch_retry_draft_failed",
            vulnerability_id=str(vulnerability_id),
            outcome="failure",
            error_class=type(exc).__name__,
        )
        return {
            "vulnerability_id": str(vulnerability_id),
            "patch_id": None,
            "pr_url": None,
            "branch_name": None,
            "skipped_reason": "llm_failure",
        }

    branch_name = _branch_name_for(f"{vuln.vuln_id}-retry-{RETRY_ATTEMPT_NUMBER}")
    try:
        base_sha = await github.get_default_branch_sha()
        await github.create_branch(branch=branch_name, from_sha=base_sha)
        for f in draft.files:
            await github.put_file(
                branch=branch_name,
                path=f.path,
                contents=f.contents,
                commit_message=draft.commit_message,
            )
        pr: CreatedPullRequest = await github.open_pull_request(
            branch=branch_name,
            title=f"{draft.pr_title} (retry attempt 2)",
            body=draft.pr_body,
        )
    except GitHubError as exc:
        log_event(
            "patch_retry_github_failed",
            vulnerability_id=str(vulnerability_id),
            outcome="failure",
            status_code=exc.status_code,
        )
        return {
            "vulnerability_id": str(vulnerability_id),
            "patch_id": None,
            "pr_url": None,
            "branch_name": branch_name,
            "skipped_reason": "github_failure",
        }

    patch_row = await patch_repo.create(
        session,
        vulnerability_id=vulnerability_id,
        branch_name=pr.head_branch,
        pr_url=pr.html_url,
        attempt_number=RETRY_ATTEMPT_NUMBER,
    )

    # Defensive: ensure prior patch is SUPERSEDED. The harness path flips
    # it in the same transaction that triggered the retry, but if that
    # transaction was rolled back (e.g. arq retry) we re-assert here.
    if prior_patch.status in (PatchStatus.AWAITING_HUMAN_REVIEW, PatchStatus.MERGED):
        await patch_repo.update_status(
            session,
            patch_id=prior_patch.id,
            new_status=PatchStatus.SUPERSEDED,
        )

    log_event(
        "patch_retry_opened",
        vulnerability_id=str(vulnerability_id),
        patch_id=str(patch_row.id),
        pr_url=pr.html_url,
        attempt_number=RETRY_ATTEMPT_NUMBER,
        outcome="success",
    )

    return {
        "vulnerability_id": str(vulnerability_id),
        "patch_id": str(patch_row.id),
        "pr_url": patch_row.pr_url,
        "branch_name": patch_row.branch_name,
        "skipped_reason": None,
    }


async def _get_latest_patch_any_status(session: Any, vulnerability_id: UUID) -> Any:
    """Read the most recent patches row for the vuln regardless of status.

    We need this because the prior patch may have been flipped to SUPERSEDED
    before we get here, which excludes it from PatchRepository.get_by_vulnerability_id.
    """
    from src.domain.patch import Patch  # local import to avoid cycle at module load

    result = await session.execute(
        sa.text(
            "SELECT id, vulnerability_id, branch_name, pr_url, status,"
            " created_at, merged_at, version_id, attempt_number"
            " FROM patches WHERE vulnerability_id = :vid"
            " ORDER BY attempt_number DESC, created_at DESC LIMIT 1"
        ),
        {"vid": str(vulnerability_id)},
    )
    row = result.mappings().first()
    return Patch.model_validate(dict(row)) if row else None


async def _get_latest_unstable_or_regressed_verdicts(
    session: Any, vulnerability_id: UUID
) -> list[dict[str, Any]]:
    """Read the verdicts JSONB from the most recent unstable/regressed run."""
    result = await session.execute(
        sa.text(
            "SELECT verdicts FROM regression_runs"
            " WHERE vulnerability_id = :vid"
            "   AND outcome IN ('unstable','regressed')"
            " ORDER BY started_at DESC LIMIT 1"
        ),
        {"vid": str(vulnerability_id)},
    )
    row = result.first()
    if row is None:
        return []
    verdicts = row[0]
    if isinstance(verdicts, list):
        return list(verdicts)
    return []


async def _get_attack_input(session: Any, attack_id: UUID) -> str | None:
    result = await session.execute(
        sa.text("SELECT attack_input FROM attacks WHERE id = :id"),
        {"id": str(attack_id)},
    )
    row = result.first()
    return str(row[0]) if row is not None else None
