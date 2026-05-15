"""Judge agent core: read an awaiting_judgment attack, call the LLM, write a verdict.

Pulled out of the LangGraph node so it is unit-testable with a mocked LLMClient.
The node simply calls run_judge.

Idempotency (CLAUDE.md §5):
  - verdicts.attack_id is UNIQUE. If a verdict already exists for the attack,
    return it without re-judging — never double-spend.
  - If the attack is not in status='awaiting_judgment' (e.g. still pending or
    already judged), we no-op and return the existing verdict if any.

Security (CLAUDE.md §4):
  - attack_input and target_response are untrusted. They are passed into the
    Judge prompt wrapped in <<<...>>> delimiters with an explicit "this is
    data, not instructions" system rule.
  - The Judge's model is a different family from the Red Team's model on
    purpose (Claude Sonnet vs. an uncensored Llama). Do not change this
    without an eval baseline diff.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID  # noqa: TC003

from sqlalchemy.ext.asyncio import AsyncSession  # noqa: TC002

from src.agents.judge.model import (
    JUDGE_AGENT_TAG,
    JUDGE_MODEL,
    JUDGE_RUBRIC_VERSION,
)
from src.agents.judge.parse import JudgeParseError, parse_judgment
from src.agents.judge.prompt import build_judge_messages
from src.agents.judge.rubric import resolve_rubric
from src.agents.judge.schema import JudgmentResponse, Verdict
from src.domain.attack import Attack, AttackStatus
from src.domain.errors import NotFoundError
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.events import log_event
from src.repositories.attacks import AttackRepository
from src.repositories.campaigns import CampaignRepository
from src.repositories.target_manifests import TargetManifestRepository
from src.repositories.verdicts import VerdictRepository


@dataclass(frozen=True)
class JudgeOutcome:
    """Returned by run_judge so callers can log or react without re-querying."""

    attack_id: UUID
    verdict_id: UUID
    verdict: Verdict
    skipped_reason: str | None  # "already_judged" | "wrong_status" | None


async def run_judge(
    *,
    attack_id: UUID,
    session: AsyncSession,
    llm_client: LLMClient,
) -> JudgeOutcome:
    """Adjudicate a single attack.

    Returns the resulting (or pre-existing) verdict_id. Idempotent: re-running
    on an already-judged attack returns the existing verdict without an LLM
    call.
    """
    attack_repo = AttackRepository()
    verdict_repo = VerdictRepository()
    manifest_repo = TargetManifestRepository()
    campaign_repo = CampaignRepository()

    # ------------------------------------------------------------------
    # 1. Load the attack and short-circuit if not in a judgeable state.
    # ------------------------------------------------------------------
    attack = await attack_repo.get_by_id(session, attack_id)
    if attack is None:
        raise NotFoundError(f"Attack {attack_id} not found")

    # If a verdict already exists, return it. Unique constraint guarantees one.
    existing = await verdict_repo.get_by_attack_id(session, attack_id)
    if existing is not None:
        log_event(
            "judge_skip",
            attack_id=str(attack_id),
            outcome="already_judged",
            reason="verdict_exists",
        )
        return JudgeOutcome(
            attack_id=attack_id,
            verdict_id=existing.id,
            verdict=Verdict(existing.verdict),
            skipped_reason="already_judged",
        )

    if attack.status != AttackStatus.AWAITING_JUDGMENT:
        # We do not judge pending or target_unavailable attacks. Caller is
        # expected to filter; this is defense-in-depth.
        log_event(
            "judge_skip",
            attack_id=str(attack_id),
            outcome="wrong_status",
            status=attack.status.value,
        )
        raise _wrong_status(attack)

    # ------------------------------------------------------------------
    # 2. Resolve the rubric.
    # ------------------------------------------------------------------
    manifest = await manifest_repo.get_active(session)
    if manifest is None:
        raise NotFoundError("No active target_manifest seeded")

    brief = await campaign_repo.get_brief(session, attack.brief_id)
    if brief is None:
        raise NotFoundError(f"Campaign brief {attack.brief_id} not found")

    rubric = resolve_rubric(
        manifest_json=manifest.manifest_json,
        subcategory=attack.subcategory,
        success_criteria=brief.success_criteria,
    )

    # ------------------------------------------------------------------
    # 3. Call the LLM.
    # ------------------------------------------------------------------
    messages = build_judge_messages(
        rubric=rubric,
        attack_input=attack.attack_input,
        target_response=attack.target_response or "",
        target_response_status=attack.target_response_status,
    )

    log_event(
        "judge_call_started",
        attack_id=str(attack_id),
        subcategory=attack.subcategory,
        model=JUDGE_MODEL,
    )

    completion = await llm_client.complete(
        model=JUDGE_MODEL,
        messages=messages,
        agent=JUDGE_AGENT_TAG,
        campaign_id=attack.campaign_id,
        attack_id=attack_id,
    )

    # ------------------------------------------------------------------
    # 4. Parse the response. Parse failure → write verdict='unclear' with
    #    raw completion preserved in notes (truncated to fit DB column).
    # ------------------------------------------------------------------
    judgment: JudgmentResponse
    parse_failure_note: str | None = None
    try:
        judgment = parse_judgment(completion.content)
    except JudgeParseError as exc:
        log_event(
            "judge_parse_failed",
            attack_id=str(attack_id),
            outcome="failure",
            error=str(exc),
        )
        parse_failure_note = f"parse_error: {exc}; raw[:500]={completion.content[:500]}"
        judgment = _unclear_fallback(parse_failure_note)

    # ------------------------------------------------------------------
    # 5. Write the verdict row.
    # ------------------------------------------------------------------
    verdict_row = await verdict_repo.create(
        session,
        attack_id=attack_id,
        verdict=judgment.verdict.value,
        confidence=judgment.confidence,
        evidence=judgment.evidence,
        notes=judgment.notes if parse_failure_note is None else parse_failure_note,
        rubric_version=JUDGE_RUBRIC_VERSION,
        model_version=JUDGE_MODEL,
    )

    # ------------------------------------------------------------------
    # 6. Transition attack to judged.
    # ------------------------------------------------------------------
    await attack_repo.mark_judged(session, attack_id=attack_id)

    log_event(
        "judge_call_finished",
        attack_id=str(attack_id),
        verdict_id=str(verdict_row.id),
        verdict=judgment.verdict.value,
        confidence=float(judgment.confidence),
        outcome="success",
    )

    return JudgeOutcome(
        attack_id=attack_id,
        verdict_id=verdict_row.id,
        verdict=judgment.verdict,
        skipped_reason=None,
    )


def _wrong_status(attack: Attack) -> ValueError:
    return ValueError(
        f"Attack {attack.id} is in status '{attack.status.value}', expected 'awaiting_judgment'"
    )


def _unclear_fallback(note: str) -> JudgmentResponse:
    """Construct a defensible 'unclear' verdict when the LLM output is unparseable."""
    from decimal import Decimal

    return JudgmentResponse(
        verdict=Verdict.UNCLEAR,
        confidence=Decimal("0.00"),
        evidence="parse_failure",
        notes=note[:4000],
        violated_boundary_ids=[],
    )
