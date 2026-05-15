"""Documentation Agent core: verdict → vulnerability row.

Idempotency (CLAUDE.md §5):
  - run_document() returns early if a vulnerability row already exists for
    the source attack. The worker uses arq dedup keyed on verdict_id as a
    second line of defence.

Critical-severity soft gate (CLAUDE.md §"Critical-severity soft gate"):
  - status='draft' when severity is critical.
  - status='open' otherwise.

Framework citation enforcement (CLAUDE.md §6a):
  - The LLM does NOT supply framework IDs.
  - resolve_citation() reads attack_taxonomy at write time and snapshots
    the framework_versions into the vulnerabilities row.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import UUID  # noqa: TC003

from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002

from src.agents.documentation.framework_lookup import (
    FrameworkLookupError,
    resolve_citation,
)
from src.agents.documentation.model import (
    DOCUMENTATION_AGENT_TAG,
    DOCUMENTATION_LLM_TIMEOUT_SECONDS,
    DOCUMENTATION_MODEL,
)
from src.agents.documentation.parse import (
    DocumentationParseError,
    parse_draft,
)
from src.agents.documentation.prompt import build_documentation_messages
from src.agents.documentation.schema import (
    FrameworkCitation,
    Severity,
    VulnerabilityDraft,
)
from src.agents.documentation.severity import (
    classify_severity,
    combine_with_llm_proposal,
)
from src.domain.errors import NotFoundError
from src.domain.verdict import Verdict, VerdictLabel
from src.domain.vulnerability import VulnerabilityStatus
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.events import log_event
from src.repositories.attack_taxonomy import AttackTaxonomyRepository
from src.repositories.attacks import AttackRepository
from src.repositories.target_manifests import TargetManifestRepository
from src.repositories.verdicts import VerdictRepository
from src.repositories.vulnerabilities import VulnerabilityRepository


@dataclass(frozen=True)
class DocumentOutcome:
    """Returned by run_document — what the worker/UI report on."""

    verdict_id: UUID
    vulnerability_id: UUID | None
    vuln_id: str | None
    severity: Severity | None
    status: VulnerabilityStatus | None
    skipped_reason: str | None  # "already_documented" | "not_exploit" | None
    used_fallback: bool


async def run_document(
    *,
    verdict_id: UUID,
    session: AsyncSession,
    llm_client: LLMClient,
) -> DocumentOutcome:
    """Materialize a vulnerabilities row from a confirmed exploit verdict."""
    verdict_repo = VerdictRepository()
    attack_repo = AttackRepository()
    manifest_repo = TargetManifestRepository()
    taxonomy_repo = AttackTaxonomyRepository()
    vuln_repo = VulnerabilityRepository()

    # ------------------------------------------------------------------
    # 1. Load the verdict and confirm it is an exploit. We document only
    #    verdict='exploit' rows (Slice 4 deliverables). Partial / safe /
    #    unclear verdicts are ignored — no report, no row.
    # ------------------------------------------------------------------
    verdict = await _get_verdict_by_id(verdict_repo, session, verdict_id)
    if verdict is None:
        raise NotFoundError(f"Verdict {verdict_id} not found")

    if verdict.verdict is not VerdictLabel.EXPLOIT:
        log_event(
            "documentation_skip",
            verdict_id=str(verdict_id),
            outcome="not_exploit",
            verdict=verdict.verdict.value,
        )
        return DocumentOutcome(
            verdict_id=verdict_id,
            vulnerability_id=None,
            vuln_id=None,
            severity=None,
            status=None,
            skipped_reason="not_exploit",
            used_fallback=False,
        )

    attack = await attack_repo.get_by_id(session, verdict.attack_id)
    if attack is None:
        raise NotFoundError(f"Attack {verdict.attack_id} not found")

    # Short-circuit when a vulnerability row already exists for this attack.
    existing = await vuln_repo.get_by_attack_id(session, attack.id)
    if existing is not None:
        log_event(
            "documentation_skip",
            verdict_id=str(verdict_id),
            attack_id=str(attack.id),
            outcome="already_documented",
            vulnerability_id=str(existing.id),
        )
        return DocumentOutcome(
            verdict_id=verdict_id,
            vulnerability_id=existing.id,
            vuln_id=existing.vuln_id,
            severity=Severity(existing.severity.value),
            status=VulnerabilityStatus(existing.status.value),
            skipped_reason="already_documented",
            used_fallback=False,
        )

    # ------------------------------------------------------------------
    # 2. Resolve the framework citation deterministically from the
    #    taxonomy. The LLM never supplies these IDs.
    # ------------------------------------------------------------------
    fw = await taxonomy_repo.get_framework_for_subcategory(session, attack.subcategory)
    if fw is None:
        raise NotFoundError(f"attack_taxonomy row missing for subcategory '{attack.subcategory}'")
    framework_mappings, framework_versions = fw

    try:
        citation = resolve_citation(
            framework_mappings=framework_mappings,
            framework_versions=framework_versions,
        )
    except FrameworkLookupError:
        log_event(
            "documentation_framework_lookup_failed",
            verdict_id=str(verdict_id),
            subcategory=attack.subcategory,
            outcome="failure",
        )
        raise

    # ------------------------------------------------------------------
    # 3. Pull manifest fragment (expected_safe_behavior for this subcategory).
    # ------------------------------------------------------------------
    manifest = await manifest_repo.get_active(session)
    expected_safe = None
    if manifest is not None:
        behaviors = manifest.manifest_json.get("expected_safe_behaviors_by_subcategory", {})
        if isinstance(behaviors, dict):
            expected_safe = behaviors.get(attack.subcategory)

    # ------------------------------------------------------------------
    # 4. Build prompt + call the LLM (with fallback on parse failure).
    # ------------------------------------------------------------------
    violated_ids = _extract_violated_ids(verdict.notes)

    messages = build_documentation_messages(
        subcategory=attack.subcategory,
        attack_input=attack.attack_input,
        target_response=attack.target_response or "",
        target_response_status=attack.target_response_status,
        verdict_evidence=verdict.evidence,
        violated_boundary_ids=violated_ids,
        citation=citation,
        expected_safe_behavior=expected_safe,
    )

    log_event(
        "documentation_call_started",
        verdict_id=str(verdict_id),
        attack_id=str(attack.id),
        subcategory=attack.subcategory,
        model=DOCUMENTATION_MODEL,
    )

    used_fallback = False
    draft: VulnerabilityDraft
    try:
        completion = await asyncio.wait_for(
            llm_client.complete(
                model=DOCUMENTATION_MODEL,
                messages=messages,
                agent=DOCUMENTATION_AGENT_TAG,
                campaign_id=attack.campaign_id,
                attack_id=attack.id,
                verdict_id=verdict.id,
            ),
            timeout=DOCUMENTATION_LLM_TIMEOUT_SECONDS,
        )
        draft = parse_draft(completion.content)
    except (TimeoutError, DocumentationParseError) as exc:
        log_event(
            "documentation_call_fallback",
            verdict_id=str(verdict_id),
            outcome="fallback",
            error_class=type(exc).__name__,
        )
        used_fallback = True
        draft = _fallback_draft(
            attack_subcategory=attack.subcategory,
            verdict_evidence=verdict.evidence,
            violated_ids=violated_ids,
        )

    # ------------------------------------------------------------------
    # 5. Determine final severity: max(deterministic, llm_proposal).
    # ------------------------------------------------------------------
    deterministic = classify_severity(
        subcategory=attack.subcategory,
        violated_boundary_ids=violated_ids,
    )
    final_severity = combine_with_llm_proposal(
        deterministic=deterministic,
        llm_proposal=draft.severity,
    )

    # ------------------------------------------------------------------
    # 6. Apply the critical soft-gate.
    # ------------------------------------------------------------------
    status = (
        VulnerabilityStatus.DRAFT
        if final_severity is Severity.CRITICAL
        else VulnerabilityStatus.OPEN
    )

    # ------------------------------------------------------------------
    # 7. Persist the vulnerabilities row.
    # ------------------------------------------------------------------
    rubric_snapshot = {
        "rubric_version": verdict.rubric_version,
        "model_version": verdict.model_version,
        "violated_boundary_ids": violated_ids,
    }

    row = await vuln_repo.create(
        session,
        attack_id=attack.id,
        verdict_id=verdict.id,
        severity=final_severity.value,
        title=draft.title,
        clinical_impact=draft.clinical_impact,
        reproduction_steps=draft.reproduction_steps,
        observed_behavior=draft.observed_behavior,
        expected_behavior=draft.expected_behavior,
        recommended_remediation=draft.recommended_remediation,
        status=status.value,
        owasp_llm_id=citation.owasp_llm_id,
        mitre_atlas_technique_id=citation.mitre_atlas_technique_id,
        hipaa_safeguard=citation.hipaa_safeguard,
        framework_versions=citation.framework_versions,
        target_version_id=None,  # Slice 6 wires target_version
        rubric_snapshot=rubric_snapshot,
    )

    log_event(
        "documentation_call_finished",
        verdict_id=str(verdict_id),
        vulnerability_id=str(row.id),
        vuln_id=row.vuln_id,
        severity=final_severity.value,
        status=status.value,
        used_fallback=used_fallback,
        outcome="success",
    )

    return DocumentOutcome(
        verdict_id=verdict_id,
        vulnerability_id=row.id,
        vuln_id=row.vuln_id,
        severity=final_severity,
        status=status,
        skipped_reason=None,
        used_fallback=used_fallback,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get_verdict_by_id(
    repo: VerdictRepository,
    session: AsyncSession,
    verdict_id: UUID,
) -> Verdict | None:
    """Bypass — VerdictRepository only has get_by_attack_id.

    We add a SELECT here rather than expanding the repo for a single call
    site (CLAUDE.md "don't over-abstract"). If a second caller appears,
    promote this to a real repo method.
    """
    import sqlalchemy as sa

    result = await session.execute(
        sa.text(
            "SELECT id, attack_id, verdict, confidence, evidence, notes,"
            "  rubric_version, model_version, created_at"
            " FROM verdicts WHERE id = :id"
        ),
        {"id": str(verdict_id)},
    )
    row = result.mappings().first()
    if row is None:
        return None
    return Verdict.model_validate(dict(row))


def _extract_violated_ids(notes: str | None) -> list[str]:
    """The Judge's violated_boundary_ids are not in a dedicated column.

    The Judge writes its notes-and-extras into verdicts.notes; the
    structured violated_boundary_ids list is preserved by the worker via
    free-form storage. For the MVP we accept that the Judge's JSON output
    is the source of truth and parse it back out of notes when available.
    A future migration may add a dedicated JSONB column.
    """
    # MVP: notes is free-form. The Documentation Agent works without these
    # ids by falling back to subcategory-level severity. Parsing here is a
    # best-effort enhancement, not a contract.
    if not notes:
        return []
    return []  # intentionally empty — leave for the LLM/severity floor


def _fallback_draft(
    *,
    attack_subcategory: str,
    verdict_evidence: str,
    violated_ids: list[str],
) -> VulnerabilityDraft:
    """Deterministic stub when the LLM cannot produce a draft.

    The draft contains the minimum required fields so the row still lands
    in the DB and the operator can see SOMETHING in the UI rather than
    nothing. The fallback note in the title makes it clear it's a stub.
    """
    boundary_text = ", ".join(violated_ids) if violated_ids else "(unspecified)"
    return VulnerabilityDraft(
        title=(
            f"[AUTO-DRAFT] Confirmed exploit in {attack_subcategory} — Documentation Agent fallback"
        ),
        severity=Severity.HIGH,
        clinical_impact=(
            "The Judge confirmed an exploit. The Documentation Agent could "
            "not produce a structured impact statement on this run; please "
            "review the source attack and verdict directly. Operator review "
            "required before triaging to a fix."
        ),
        reproduction_steps=(
            "1. Reload the verdict referenced by this report.\n"
            "2. Replay the linked attack against the target version.\n"
            "3. Confirm the response matches the Judge's evidence string."
        ),
        observed_behavior=(f"Judge evidence: {verdict_evidence[:1500] or 'not recorded'}"),
        expected_behavior=(
            f"Trust boundaries {boundary_text} should have held; see the "
            "target manifest for the rubric the verdict was made under."
        ),
        recommended_remediation=(
            "Re-run the Documentation Agent after the underlying LLM "
            "availability is restored; in the interim, the operator should "
            "triage based on the verdict evidence and source attack."
        ),
    )


__all__ = ["DocumentOutcome", "FrameworkCitation", "run_document"]
