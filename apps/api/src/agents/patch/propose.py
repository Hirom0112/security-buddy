"""Patch Agent core: vulnerability → GitHub PR.

Pipeline:
  1. Load the Vulnerability row (must be status='open' — critical drafts
     are gated, regressed/patched vulns are out of scope).
  2. Short-circuit if a patch already exists for the vulnerability.
  3. LLM call 1 — code search → FileSelection (candidate file paths).
  4. LLM call 2 — diff generation → PatchDraft (commit + files + PR body).
  5. GitHub: create branch, write each file, open PR.
  6. Persist patches row with status='awaiting_human_review'.

Architectural notes (CLAUDE.md):
  - §5 Idempotency: short-circuit on existing patch; arq dedups on
    vulnerability_id; partial unique index on (vulnerability_id) for
    active patches is the schema-level backstop.
  - §2 Security: no shell, no subprocess, no clone-to-disk. The Patch
    Agent only talks to api.github.com.
  - §4 Untrusted output: the diff is data, not instructions. Nothing
    here templates the LLM output into another LLM prompt.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID  # noqa: TC003

from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002

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
from src.domain.errors import NotFoundError
from src.domain.vulnerability import VulnerabilityStatus
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.events import log_event
from src.repositories.patches import PatchRepository
from src.repositories.vulnerabilities import VulnerabilityRepository

if TYPE_CHECKING:
    from src.agents.patch.schema import PatchDraft
    from src.domain.patch import Patch

# Safe branch-name pattern: lowercase alnum + hyphens + slashes.
_BRANCH_SLUG_RE = re.compile(r"[^a-z0-9/-]+")


@dataclass(frozen=True)
class ProposeOutcome:
    """Returned by run_propose — what the worker reports back."""

    vulnerability_id: UUID
    patch_id: UUID | None
    branch_name: str | None
    pr_url: str | None
    # One of: already_patched | not_open | missing_settings | llm_failure | github_failure
    skipped_reason: str | None


def _branch_name_for(vuln_id_str: str) -> str:
    """Compute a deterministic branch name for a vulnerability."""
    slug = _BRANCH_SLUG_RE.sub("-", vuln_id_str.lower()).strip("-")
    return f"security-buddy/{slug}"


async def run_propose(
    *,
    vulnerability_id: UUID,
    session: AsyncSession,
    llm_client: LLMClient,
    github: GitHubClient,
) -> ProposeOutcome:
    """Open a PR proposing a fix for the given vulnerability."""
    vuln_repo = VulnerabilityRepository()
    patch_repo = PatchRepository()

    # --------------------------------------------------------------
    # 1. Load + gate
    # --------------------------------------------------------------
    vuln = await vuln_repo.get_by_id(session, vulnerability_id)
    if vuln is None:
        raise NotFoundError(f"Vulnerability {vulnerability_id} not found")

    if vuln.status is not VulnerabilityStatus.OPEN:
        log_event(
            "patch_skip",
            vulnerability_id=str(vulnerability_id),
            outcome="not_open",
            status=vuln.status.value,
        )
        return ProposeOutcome(
            vulnerability_id=vulnerability_id,
            patch_id=None,
            branch_name=None,
            pr_url=None,
            skipped_reason="not_open",
        )

    existing = await patch_repo.get_by_vulnerability_id(session, vulnerability_id)
    if existing is not None:
        log_event(
            "patch_skip",
            vulnerability_id=str(vulnerability_id),
            outcome="already_patched",
            patch_id=str(existing.id),
        )
        return ProposeOutcome(
            vulnerability_id=vulnerability_id,
            patch_id=existing.id,
            branch_name=existing.branch_name,
            pr_url=existing.pr_url,
            skipped_reason="already_patched",
        )

    # --------------------------------------------------------------
    # 2. LLM call 1 — code search
    # --------------------------------------------------------------
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

    log_event(
        "patch_codesearch_started",
        vulnerability_id=str(vulnerability_id),
        model=PATCH_MODEL,
    )

    try:
        sel_completion = await asyncio.wait_for(
            llm_client.complete(
                model=PATCH_MODEL,
                messages=selection_messages,
                agent=PATCH_AGENT_TAG,
                campaign_id=None,
                attack_id=vuln.attack_id,
                verdict_id=vuln.verdict_id,
            ),
            timeout=PATCH_LLM_TIMEOUT_SECONDS,
        )
        selection = parse_file_selection(sel_completion.content)
    except (TimeoutError, PatchParseError) as exc:
        log_event(
            "patch_codesearch_failed",
            vulnerability_id=str(vulnerability_id),
            outcome="failure",
            error_class=type(exc).__name__,
        )
        return ProposeOutcome(
            vulnerability_id=vulnerability_id,
            patch_id=None,
            branch_name=None,
            pr_url=None,
            skipped_reason="llm_failure",
        )

    candidate_paths = selection.file_paths[:PATCH_MAX_CANDIDATE_FILES]

    # --------------------------------------------------------------
    # 3. LLM call 2 — diff generation
    # --------------------------------------------------------------
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

    log_event(
        "patch_draft_started",
        vulnerability_id=str(vulnerability_id),
        candidate_file_count=len(candidate_paths),
        model=PATCH_MODEL,
    )

    try:
        draft_completion = await asyncio.wait_for(
            llm_client.complete(
                model=PATCH_MODEL,
                messages=draft_messages,
                agent=PATCH_AGENT_TAG,
                campaign_id=None,
                attack_id=vuln.attack_id,
                verdict_id=vuln.verdict_id,
            ),
            timeout=PATCH_LLM_TIMEOUT_SECONDS,
        )
        draft: PatchDraft = parse_patch_draft(draft_completion.content)
    except (TimeoutError, PatchParseError) as exc:
        log_event(
            "patch_draft_failed",
            vulnerability_id=str(vulnerability_id),
            outcome="failure",
            error_class=type(exc).__name__,
        )
        return ProposeOutcome(
            vulnerability_id=vulnerability_id,
            patch_id=None,
            branch_name=None,
            pr_url=None,
            skipped_reason="llm_failure",
        )

    # --------------------------------------------------------------
    # 4. GitHub: branch + commits + PR
    # --------------------------------------------------------------
    branch_name = _branch_name_for(vuln.vuln_id)
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
            title=draft.pr_title,
            body=draft.pr_body,
        )
    except GitHubError as exc:
        log_event(
            "patch_github_failed",
            vulnerability_id=str(vulnerability_id),
            outcome="failure",
            status_code=exc.status_code,
        )
        return ProposeOutcome(
            vulnerability_id=vulnerability_id,
            patch_id=None,
            branch_name=branch_name,
            pr_url=None,
            skipped_reason="github_failure",
        )

    # --------------------------------------------------------------
    # 5. Persist patches row + flip vulnerability → proposed_fix
    # --------------------------------------------------------------
    patch_row: Patch = await patch_repo.create(
        session,
        vulnerability_id=vulnerability_id,
        branch_name=pr.head_branch,
        pr_url=pr.html_url,
    )

    await vuln_repo.update_status(
        session,
        vulnerability_id=vulnerability_id,
        new_status=VulnerabilityStatus.PROPOSED_FIX,
    )

    log_event(
        "patch_opened",
        vulnerability_id=str(vulnerability_id),
        patch_id=str(patch_row.id),
        pr_url=pr.html_url,
        pr_number=pr.number,
        outcome="success",
    )

    return ProposeOutcome(
        vulnerability_id=vulnerability_id,
        patch_id=patch_row.id,
        branch_name=patch_row.branch_name,
        pr_url=patch_row.pr_url,
        skipped_reason=None,
    )
