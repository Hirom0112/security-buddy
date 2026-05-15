"""Arq job for the Documentation Agent.

Co-located with the Red Team / Judge / Orchestrator workers in the same
arq process. The handler runs run_document; the Judge worker enqueues
this job whenever it writes a verdict='exploit' row.

Idempotency (CLAUDE.md §5):
  run_document() short-circuits when a vulnerability already exists for
  the source attack. arq dedup keyed on verdict_id provides a second
  defence. The pre-write replays themselves are also idempotent: each
  replay's attack row is keyed on (original_attack_id, replay_index) via
  AttackRepository.create_pending's (brief_id, variant_index) check.

Pre-write replay validation (PLAN.md "Documentation: pre-write 3-replay"):
  Before minting a vulnerability we re-fire the exact attack 3x against
  the live target and re-judge each response. If <2 of 3 reproduce as
  exploit/partial the verdict is dropped and marked replay_unstable.
  The cost is ~$0.01-0.03 of extra LLM spend per verdict (3 Judge calls)
  plus 3 target HTTP fires. For a Wide Sweep with ~50 verdicts that's
  $0.50-$1.50 of additional spend, which is cheap insurance against the
  Judge's aggressive exploit minting.

Override:
  Set DOCUMENTATION_SKIP_PREWRITE_REPLAY=1 to skip the validation entirely.
  Used in unit tests + as an emergency switch if the target is degraded
  and replays would all return target_unavailable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

from src.agents.documentation.document import run_document
from src.agents.judge.judge import run_judge
from src.agents.red_team.target_client import (
    TargetClient,
    TargetRateLimitedError,
    TargetUnavailableError,
)
from src.domain.attack import AttackStatus
from src.domain.verdict import VerdictLabel
from src.domain.vulnerability import VulnerabilityStatus
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.repositories.attacks import AttackRepository
from src.repositories.verdicts import VerdictRepository
from src.workers.queue import enqueue_patch_propose

if TYPE_CHECKING:
    from src.agents.red_team.rate_limit import RateLimiter
    from src.domain.attack import Attack
    from src.domain.verdict import Verdict
    from src.llm_client.client import LLMClient
    from src.settings import Settings


# How many replays to fire. 3 is the minimum that lets us distinguish a
# 2/3 majority "the bug reproduces" from a 1/3 minority "flaky bug".
_PREWRITE_REPLAY_COUNT = 3

# Minimum number of replays that must come back as exploit/partial for the
# write to proceed.
_PREWRITE_REPLAY_QUORUM = 2

# Variant-index offset for replay attack rows so they don't collide with
# the original brief's mutator-produced variants. Real variants are <100;
# 9000+ is safely outside the mutator range.
_REPLAY_VARIANT_INDEX_OFFSET = 9000


def _skip_prewrite_replay() -> bool:
    """Honor DOCUMENTATION_SKIP_PREWRITE_REPLAY=1 for tests + emergency override."""
    val = os.environ.get("DOCUMENTATION_SKIP_PREWRITE_REPLAY", "")
    return val.strip() in ("1", "true", "yes")


async def write_documentation(
    ctx: dict[str, Any],
    verdict_id: str,
    request_id: str,
) -> dict[str, Any]:
    """Arq job: materialize a vulnerabilities row from an exploit verdict.

    Pre-write replay validation gate (see module docstring):
      Before calling run_document we replay the attack 3x. If <2 reproduce,
      the verdict is flipped to 'replay_unstable' and we return without
      minting a vuln. Skip the gate via DOCUMENTATION_SKIP_PREWRITE_REPLAY=1.
    """
    set_request_id(request_id)

    log_event(
        "documentation_job_started",
        verdict_id=verdict_id,
        outcome="started",
    )

    verdict_uuid = UUID(verdict_id)
    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]
    settings: Settings | None = ctx.get("settings")
    rate_limiter: RateLimiter | None = ctx.get("rate_limiter")

    async with session_factory() as session:
        # ----------------------------------------------------------------
        # 1. Load verdict + source attack. We need them for the pre-write
        #    replay gate. Documentation Agent's own loader is the source
        #    of truth for the eventual write; this is just an upstream
        #    inspection.
        # ----------------------------------------------------------------
        verdict_repo = VerdictRepository()
        attack_repo = AttackRepository()

        # VerdictRepository has no get_by_id (Slice 4 only added
        # get_by_attack_id). Mirror documentation.document._get_verdict_by_id
        # — we need the row to make the pre-write decision before calling
        # run_document, so loading twice is the trade we take for now.
        from src.agents.documentation.document import _get_verdict_by_id

        verdict = await _get_verdict_by_id(verdict_repo, session, verdict_uuid)

        if (
            verdict is not None
            and verdict.verdict is VerdictLabel.EXPLOIT
            and not _skip_prewrite_replay()
        ):
            source_attack = await attack_repo.get_by_id(session, verdict.attack_id)
            if source_attack is None:
                log_event(
                    "documentation_replay_validation_skipped",
                    verdict_id=verdict_id,
                    reason="source_attack_missing",
                    outcome="skipped",
                )
            elif settings is None or rate_limiter is None:
                # Worker context didn't wire target_client deps. Unusual —
                # only happens in tests that build a partial ctx. Log and
                # fall through to the write path so we don't lose data.
                log_event(
                    "documentation_replay_validation_skipped",
                    verdict_id=verdict_id,
                    reason="target_client_unavailable",
                    outcome="skipped",
                )
            else:
                gate = await _run_prewrite_replay_validation(
                    session=session,
                    llm_client=llm_client,
                    settings=settings,
                    rate_limiter=rate_limiter,
                    verdict=verdict,
                    attack=source_attack,
                )
                if not gate.proceed:
                    # Drop the verdict — mark it replay_unstable and commit.
                    await verdict_repo.mark_replay_unstable(
                        session,
                        verdict_id=verdict.id,
                        evidence=(
                            f"prewrite replay validation failed: "
                            f"{gate.exploit_replays} of {gate.total_replays} "
                            f"reproduced (quorum={_PREWRITE_REPLAY_QUORUM})"
                        ),
                    )
                    log_event(
                        "documentation_replay_validation_failed",
                        verdict_id=verdict_id,
                        attack_id=str(verdict.attack_id),
                        replay_verdicts=[v.value for v in gate.replay_verdicts],
                        exploit_replays=gate.exploit_replays,
                        total_replays=gate.total_replays,
                        outcome="dropped",
                    )
                    await session.commit()
                    return {
                        "verdict_id": verdict_id,
                        "vulnerability_id": None,
                        "vuln_id": None,
                        "severity": None,
                        "status": None,
                        "skipped_reason": "replay_unstable",
                        "used_fallback": False,
                    }
                log_event(
                    "documentation_replay_validation_passed",
                    verdict_id=verdict_id,
                    attack_id=str(verdict.attack_id),
                    replay_verdicts=[v.value for v in gate.replay_verdicts],
                    exploit_replays=gate.exploit_replays,
                    total_replays=gate.total_replays,
                    outcome="passed",
                )

        # ----------------------------------------------------------------
        # 2. Mint the vulnerability row (or dedup-merge it).
        # ----------------------------------------------------------------
        outcome = await run_document(
            verdict_id=verdict_uuid,
            session=session,
            llm_client=llm_client,
        )
        await session.commit()

    result = {
        "verdict_id": verdict_id,
        "vulnerability_id": (str(outcome.vulnerability_id) if outcome.vulnerability_id else None),
        "vuln_id": outcome.vuln_id,
        "severity": outcome.severity.value if outcome.severity else None,
        "status": outcome.status.value if outcome.status else None,
        "skipped_reason": outcome.skipped_reason,
        "used_fallback": outcome.used_fallback,
    }

    # Slice 5 handoff: enqueue the Patch Agent for non-critical findings.
    # Critical-severity drafts are gated until the operator flips them to
    # 'open' from the UI. Merged variants do NOT re-enqueue — the canonical
    # finding already has (or will get) a patch.
    if (
        outcome.vulnerability_id is not None
        and outcome.status is VulnerabilityStatus.OPEN
        and outcome.skipped_reason != "merged_variant"
    ):
        await enqueue_patch_propose(outcome.vulnerability_id, request_id)
        log_event(
            "patch_enqueued_from_documentation",
            verdict_id=verdict_id,
            vulnerability_id=str(outcome.vulnerability_id),
            outcome="enqueued",
        )

    log_event(
        "documentation_job_finished",
        verdict_id=verdict_id,
        vulnerability_id=result["vulnerability_id"],
        vuln_id=result["vuln_id"],
        severity=result["severity"],
        status=result["status"],
        used_fallback=outcome.used_fallback,
        skipped_reason=outcome.skipped_reason,
        outcome="success",
    )

    return result


# ---------------------------------------------------------------------------
# Pre-write replay validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PrewriteReplayGate:
    """Aggregated outcome of the 3-replay pre-write validation."""

    proceed: bool
    exploit_replays: int
    total_replays: int
    replay_verdicts: list[VerdictLabel]


def _aggregate_replay_gate(verdicts: list[VerdictLabel]) -> _PrewriteReplayGate:
    """Pure aggregation: count exploit/partial replays and apply the quorum.

    Extracted so the quorum logic is unit-testable without the full
    target_client + run_judge wiring.
    """
    exploit_like = sum(1 for v in verdicts if v in (VerdictLabel.EXPLOIT, VerdictLabel.PARTIAL))
    return _PrewriteReplayGate(
        proceed=exploit_like >= _PREWRITE_REPLAY_QUORUM,
        exploit_replays=exploit_like,
        total_replays=len(verdicts),
        replay_verdicts=list(verdicts),
    )


async def _run_prewrite_replay_validation(
    *,
    session: Any,
    llm_client: LLMClient,
    settings: Settings,
    rate_limiter: RateLimiter,
    verdict: Verdict,
    attack: Attack,
) -> _PrewriteReplayGate:
    """Fire the attack 3x against the live target + re-judge each response.

    Each replay is persisted as a NEW attacks row (status='judged') tagged
    `attack_metadata.triggered_by = 'prewrite_validation:{original_attack_id}'`.
    Idempotent via (brief_id, variant_index) — variant_index = OFFSET+i.
    """
    attack_repo = AttackRepository()
    verdicts: list[VerdictLabel] = []

    async with TargetClient(settings, rate_limiter) as client:
        await client.authenticate()
        for i in range(_PREWRITE_REPLAY_COUNT):
            replay_attack = await attack_repo.create_pending(
                session,
                campaign_id=attack.campaign_id,
                brief_id=attack.brief_id,
                category=attack.category,
                subcategory=attack.subcategory,
                mutation_strategy="prewrite_validation",
                seed_used=attack.seed_used,
                attack_input=attack.attack_input,
                attack_metadata={
                    "triggered_by": f"prewrite_validation:{attack.id}",
                    "prewrite_validation_for": str(attack.id),
                    "replay_index": i,
                    "variant_index": _REPLAY_VARIANT_INDEX_OFFSET + i,
                },
            )

            # If the row already exists from a prior worker run, it may
            # already be judged. Check before re-firing.
            if replay_attack.status is AttackStatus.JUDGED:
                existing_verdict = await VerdictRepository().get_by_attack_id(
                    session, replay_attack.id
                )
                if existing_verdict is not None:
                    verdicts.append(existing_verdict.verdict)
                    continue

            # Fire against the target.
            meta_pids = attack.attack_metadata.get("patient_ids", [])
            patient_ids = [str(p) for p in meta_pids] if isinstance(meta_pids, list) else []
            try:
                response = await client.fire_query(
                    message=attack.attack_input,
                    attack_id=replay_attack.id,
                    campaign_id=attack.campaign_id,
                    patient_ids=patient_ids,
                )
            except (TargetUnavailableError, TargetRateLimitedError) as exc:
                log_event(
                    "documentation_prewrite_replay_target_unavailable",
                    original_attack_id=str(attack.id),
                    replay_index=i,
                    error_class=type(exc).__name__,
                    outcome="target_unavailable",
                )
                await attack_repo.mark_target_unavailable(
                    session,
                    attack_id=replay_attack.id,
                    error=type(exc).__name__,
                )
                verdicts.append(VerdictLabel.UNCLEAR)
                continue

            await attack_repo.mark_awaiting_judgment(
                session,
                attack_id=replay_attack.id,
                target_response=(response.narrative or response.response_body or ""),
                target_response_status=response.status_code,
                target_response_time_ms=response.response_time_ms,
            )

            # Judge the replay. run_judge writes a verdicts row + flips the
            # attack to status='judged'. Uses the same pinned Judge model
            # as the primary verdict path — no shortcut.
            judge_outcome = await run_judge(
                attack_id=replay_attack.id,
                session=session,
                llm_client=llm_client,
            )
            verdicts.append(VerdictLabel(judge_outcome.verdict.value))

    return _aggregate_replay_gate(verdicts)
