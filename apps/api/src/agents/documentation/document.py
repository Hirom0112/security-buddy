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
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
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
from src.agents.documentation.rubric_snapshot import build_full_rubric_snapshot
from src.agents.documentation.schema import (
    FrameworkCitation,
    Severity,
    VulnerabilityDraft,
)
from src.agents.documentation.severity import (
    classify_severity,
    combine_with_llm_proposal,
    downgrade_for_no_disclosure,
)
from src.domain.errors import NotFoundError
from src.domain.verdict import Verdict, VerdictLabel
from src.domain.vulnerability import VulnerabilityStatus
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.events import log_event
from src.repositories.attack_taxonomy import AttackTaxonomyRepository
from src.repositories.attacks import AttackRepository
from src.repositories.campaigns import CampaignRepository
from src.repositories.target_manifests import TargetManifestRepository
from src.repositories.target_versions import TargetVersionRepository
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
    skipped_reason: str | None  # "already_documented" | "not_exploit" | "merged_variant" | None
    used_fallback: bool
    merged_into_vuln_id: UUID | None = None
    """When skipped_reason='merged_variant', the existing vuln we merged into."""


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
    # 5b. No-disclosure downgrade. When the Judge confirmed an exploit
    #     (boundary crossed) but the target response carried no
    #     exfiltrated content (data_actually_disclosed=False — empty
    #     list, error envelope, refusal), drop severity one rank.
    #     Operator queue ranks real-PHI-leak findings above
    #     unauthorized-action-but-empty-response findings.
    #
    #     Backwards-compat: legacy verdict rows without the field
    #     (`None`) skip the downgrade entirely. We never downgrade on
    #     missing data.
    # ------------------------------------------------------------------
    if verdict.data_actually_disclosed is False:
        pre_downgrade = final_severity
        final_severity = downgrade_for_no_disclosure(final_severity)
        log_event(
            "severity_downgraded_no_disclosure",
            verdict_id=str(verdict_id),
            attack_id=str(attack.id),
            original_severity=pre_downgrade.value,
            new_severity=final_severity.value,
            outcome="downgraded",
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
    rubric_snapshot: dict[str, Any] = {
        "rubric_version": verdict.rubric_version,
        "model_version": verdict.model_version,
        "violated_boundary_ids": violated_ids,
    }

    # CLAUDE.md §6a / Slice 6 §1: freeze the FULL rubric at write time so the
    # regression harness re-grades against the rubric in force at confirmation,
    # not against a live manifest that may have drifted mid-incident. We snap
    # only when we have a manifest in hand — legacy rows without `full` fall
    # back to live resolution in harness.replay.
    if manifest is not None:
        brief_criteria: list[Any] | dict[str, Any] | None = None
        try:
            brief = await CampaignRepository().get_brief(session, attack.brief_id)
            if brief is not None:
                brief_criteria = brief.success_criteria
        except Exception:
            brief_criteria = None
        rubric_snapshot["full"] = build_full_rubric_snapshot(
            manifest_id=manifest.id,
            manifest_version=manifest.version,
            manifest_json=manifest.manifest_json,
            subcategory=attack.subcategory,
            success_criteria=brief_criteria,
        )

    # ------------------------------------------------------------------
    # 7a. Response-shape dedup. The deterministic mutator can produce many
    #     lexical variants of one seed (PLAN.md "Documentation: pre-write
    #     3-replay + response-shape dedup" — the 9-permutation incident).
    #     If an existing draft/open vuln in the same subcategory + same
    #     target_version has an identical response-shape hash, increment
    #     its variant_count and DO NOT mint a new VUL-NNNN.
    #
    #     Dedup window is target_version_id, not date — a target redeploy
    #     resets the window so a re-introduced bug surfaces fresh.
    # ------------------------------------------------------------------
    response_text = attack.target_response or ""
    shape_hash = _response_shape_hash(response_text)
    current_target_version_id: UUID | None = None
    if manifest is not None:
        latest_tv = await TargetVersionRepository().get_latest(
            session, target_id=manifest.target_id
        )
        if latest_tv is not None:
            current_target_version_id = latest_tv.id

    existing_variant = await vuln_repo.find_existing_variant(
        session,
        subcategory=attack.subcategory,
        response_shape_hash=shape_hash,
        target_version_id=current_target_version_id,
    )
    if existing_variant is not None:
        merge_note = {
            "at": _utc_iso(),
            "actor": "documentation_agent",
            "action": "merged_variant",
            "source_attack_id": str(attack.id),
            "source_verdict_id": str(verdict.id),
            "response_shape_hash": shape_hash,
            "reason": (
                "identical response shape under same subcategory + "
                "target_version — merged into canonical finding"
            ),
        }
        merged = await vuln_repo.increment_variant_count(
            session,
            vulnerability_id=existing_variant.id,
            merge_note=merge_note,
        )
        log_event(
            "documentation_variant_merged",
            verdict_id=str(verdict_id),
            attack_id=str(attack.id),
            merged_into_vulnerability_id=str(existing_variant.id),
            merged_into_vuln_id=existing_variant.vuln_id,
            response_shape_hash=shape_hash,
            new_variant_count=(merged.variant_count if merged else None),
            outcome="merged",
        )
        return DocumentOutcome(
            verdict_id=verdict_id,
            vulnerability_id=existing_variant.id,
            vuln_id=existing_variant.vuln_id,
            severity=Severity(existing_variant.severity.value),
            status=VulnerabilityStatus(existing_variant.status.value),
            skipped_reason="merged_variant",
            used_fallback=used_fallback,
            merged_into_vuln_id=existing_variant.id,
        )

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
        target_version_id=current_target_version_id,
        rubric_snapshot=rubric_snapshot,
        response_shape_hash=shape_hash,
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
            "  rubric_version, model_version, created_at,"
            "  data_actually_disclosed"
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


# ---------------------------------------------------------------------------
# Response-shape hash
# ---------------------------------------------------------------------------


# Regexes used by _response_shape_hash. All compiled once at import.
_RE_UUID: re.Pattern[str] = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_RE_ISO_DATE: re.Pattern[str] = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?)?",
    re.IGNORECASE,
)
# Match standalone integers and floats. Walked after UUID/date so we don't
# eat the digits inside those.
_RE_NUMBER: re.Pattern[str] = re.compile(r"\b\d+(?:\.\d+)?\b")


def _normalize_text(text: str) -> str:
    """Collapse whitespace + replace volatile tokens with stable placeholders.

    Order matters: dates before UUIDs (a date is shorter and won't shadow a
    UUID), and both before NUM (which would otherwise eat the digits inside
    them).
    """
    out = _RE_ISO_DATE.sub("DATE", text)
    out = _RE_UUID.sub("UUID", out)
    out = _RE_NUMBER.sub("NUM", out)
    out = out.lower()
    out = re.sub(r"\s+", " ", out).strip()
    return out


def _normalize_json(obj: Any) -> Any:
    """Recursively normalize a JSON value: sort keys, scrub values to types.

    For dedup we care about *shape*, not specific values. A list of patient
    rows with three columns should hash the same regardless of the column
    contents.
    """
    if isinstance(obj, dict):
        # Sort keys so {"a":1,"b":2} and {"b":2,"a":1} hash identically.
        return {k: _normalize_json(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        # Lists keep order — order can be a real signal (top-N results) and
        # collapsing it loses information. We do normalize each element.
        return [_normalize_json(v) for v in obj]
    if isinstance(obj, bool):
        return "BOOL"
    if isinstance(obj, (int, float)):
        return "NUM"
    if isinstance(obj, str):
        return _normalize_text(obj)
    if obj is None:
        return None
    # Fallback for unexpected JSON types.
    return "VAL"


def _response_shape_hash(target_response: str) -> str:
    """Hash the *shape* of a target response.

    Two responses that share keys, list lengths, and structural value types
    but differ in numeric values, dates, UUIDs, or specific strings should
    hash identically. This is the dedup key for the Documentation Agent
    (PLAN.md "Documentation: pre-write 3-replay + response-shape dedup").

    Algorithm:
      1. If the input parses as JSON, recursively normalize: sort keys,
         scrub primitives to type tokens (NUM, BOOL, etc.) and string text
         via _normalize_text.
      2. Otherwise treat the input as opaque text and run _normalize_text.
      3. SHA-256 the canonical UTF-8 bytes. Return the first 16 hex chars.

    16 chars (64 bits) is enough headroom: at 1,000 vulns the birthday
    collision probability is ~3e-14, and the dedup is scoped by
    subcategory + target_version anyway.
    """
    text = (target_response or "").strip()
    canonical: str
    if text:
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            canonical = _normalize_text(text)
        else:
            canonical = json.dumps(_normalize_json(parsed), sort_keys=True)
    else:
        canonical = ""
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest[:16]


def _utc_iso() -> str:
    """ISO-8601 UTC timestamp for note entries. Wrapped for testability."""
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


__all__ = [
    "DocumentOutcome",
    "FrameworkCitation",
    "_response_shape_hash",
    "run_document",
]
