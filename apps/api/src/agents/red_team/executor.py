"""Red Team execution loop for Slice 1D.

Connects seeds + mutations + target client + repositories into a single
async execution function that the LangGraph node and arq worker both call.

Idempotency contract (CLAUDE.md §5):
  - Checks brief.status == 'completed' before doing any work. If already
    completed, returns early with zero writes.
  - For each variant_index, calls AttackRepository.create_pending() which
    internally checks the (brief_id, variant_index) pair and returns the
    existing row rather than inserting a duplicate.
  - On any crash mid-loop, re-running will skip already-created attacks
    (they exist and their variant_index is present in attack_metadata) and
    skip already-executed attacks (mark_awaiting_judgment is idempotent).

Security (CLAUDE.md §4):
  - Attack payloads are data, not instructions. They are passed as strings
    into HTTP request bodies only — never eval'd, never templated into other
    prompts.
  - No secrets in logs. log_event() redaction layer handles it.
  - No shell access, no subprocess.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

from src.agents.red_team.mutations.base import AsyncMutationStrategy
from src.agents.red_team.mutations.registry import get_strategy
from src.agents.red_team.rate_limit import CampaignAttackCapReached, RateLimiter
from src.agents.red_team.seed_loader import load_seeds_for_subcategory
from src.agents.red_team.target_client import TargetClient, TargetUnavailableError
from src.agents.red_team.types import MutationStrategyName, SeedAttack, Variant  # noqa: TC001
from src.domain.attack import AttackStatus
from src.domain.campaign import BriefStatus, CampaignStatus
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.events import log_event
from src.repositories.attacks import AttackRepository
from src.repositories.campaigns import CampaignRepository
from src.settings import Settings  # noqa: TC001

# Callable signature for the optional Judge-enqueue hook. The executor invokes
# this once per attack that transitions to awaiting_judgment so that Judge
# evaluation is fanned out incrementally (TODO #59). Kept as a Callable rather
# than a direct import so that src.agents.red_team remains independent of
# src.workers (import-linter contract: agents-mutually-independent + no
# leaf-package may import workers).
JudgeEnqueuer = Callable[[UUID, str], Awaitable[None]]

# Ordered rotation of mutation strategies applied round-robin across variants.
# The "llm" slot is only used when an LLMClient is wired into run_executor;
# otherwise the rotation collapses to the three deterministic strategies.
_STRATEGY_ROTATION_FULL: list[MutationStrategyName] = [
    "lexical",
    "structural",
    "multi_turn",
    "llm",
]
_STRATEGY_ROTATION_DETERMINISTIC: list[MutationStrategyName] = [
    "lexical",
    "structural",
    "multi_turn",
]

# Patient IDs used for synthetic test data (never real PHI — CLAUDE.md §3).
_SYNTHETIC_PATIENT_IDS: list[str] = ["pt-001", "pt-007", "pt-018", "pt-027"]


def _serialize_attack_input(attack_input: str | list[str]) -> str:
    """Serialize attack_input to a string suitable for DB storage.

    Single-turn: stored as-is.
    Multi-turn: stored as a JSON array string — the Judge decodes it.
    """
    if isinstance(attack_input, list):
        return json.dumps(attack_input)
    return attack_input


async def run_executor(
    *,
    brief_id: UUID,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
    judge_enqueuer: JudgeEnqueuer | None = None,
    request_id: str | None = None,
    llm_client: LLMClient | None = None,
) -> dict[str, object]:
    """Execute the Red Team loop for a single campaign brief.

    Args:
        brief_id: UUID of the campaign_brief row to execute.
        session_factory: SQLAlchemy async session factory.
        settings: Application settings (target URLs, credentials).
        rate_limiter: Shared outbound rate limiter (enforced before every
            TargetClient.fire_query call).
        judge_enqueuer: Optional callable invoked once per attack that
            transitions to awaiting_judgment, taking (attack_id, request_id).
            Wired by the arq worker to enqueue Judge incrementally (TODO #59).
            When None, the executor returns awaiting_judgment_attack_ids so
            callers can fan out themselves (legacy / LangGraph path).
        request_id: Correlation id passed through to judge_enqueuer. Required
            when judge_enqueuer is provided; ignored otherwise.

    Returns:
        A dict with:
          - completed_attack_count: int
          - halted_reason: str | None (None when all variants completed normally)
          - awaiting_judgment_attack_ids: list[str] of attack IDs that
            transitioned to awaiting_judgment during this invocation. When
            judge_enqueuer is provided, these have ALREADY been enqueued for
            Judge — callers must not re-enqueue.

    Idempotency for per-attack Judge enqueue (TODO #59):
        Gating on AttackRepository.create_pending() returning status ==
        PENDING_EXECUTION means an attack only progresses through the
        fire-and-enqueue path on its first observation. A retried executor
        for the same brief sees status awaiting_judgment / judged on the
        existing rows and skips both firing and enqueueing. arq's
        _job_id="judge:{attack_id}" in enqueue_judge_evaluate provides a
        second layer of dedup on the queue side.

    The function is idempotent: calling it twice for the same brief_id
    returns early on the second call without any duplicate writes.
    """
    if judge_enqueuer is not None and request_id is None:
        raise ValueError("request_id is required when judge_enqueuer is provided")
    campaign_repo = CampaignRepository()
    attack_repo = AttackRepository()

    # ------------------------------------------------------------------
    # Step 1: Load brief and check idempotency guard.
    # ------------------------------------------------------------------
    async with session_factory() as session:
        brief = await campaign_repo.get_brief(session, brief_id)
        if brief is None:
            log_event(
                "red_team_executor_brief_not_found",
                brief_id=str(brief_id),
                outcome="error",
            )
            raise ValueError(f"Campaign brief {brief_id} not found")

        campaign = await campaign_repo.get(session, brief.campaign_id)
        if campaign is None:
            raise ValueError(f"Campaign {brief.campaign_id} not found")

        if brief.status == BriefStatus.COMPLETED:
            log_event(
                "red_team_executor_skipped",
                brief_id=str(brief_id),
                campaign_id=str(brief.campaign_id),
                reason="already_completed",
                outcome="idempotent_skip",
            )
            # Count how many attacks exist for reporting.
            async with session_factory() as count_session:
                from sqlalchemy import text as sa_text

                result = await count_session.execute(
                    sa_text("SELECT COUNT(*) FROM attacks WHERE brief_id = :brief_id"),
                    {"brief_id": str(brief_id)},
                )
                row = result.first()
                existing_count: int = int(row[0]) if row else 0
            return {"completed_attack_count": existing_count, "halted_reason": None}

    # ------------------------------------------------------------------
    # Step 2: Load seeds for the brief's target_subcategory.
    # ------------------------------------------------------------------
    seeds: list[SeedAttack] = load_seeds_for_subcategory(brief.target_subcategory)
    if not seeds:
        log_event(
            "red_team_executor_no_seeds",
            brief_id=str(brief_id),
            subcategory=brief.target_subcategory,
            outcome="halted",
        )
        async with session_factory() as session:
            await campaign_repo.update_status(
                session,
                campaign_id=campaign.id,
                status=CampaignStatus.NO_CANDIDATES,
                expected_version_id=campaign.version_id,
            )
            await session.commit()
        return {"completed_attack_count": 0, "halted_reason": "no_seeds"}

    # ------------------------------------------------------------------
    # Step 3: Build variant schedule (deterministic round-robin).
    # The schedule is (seed_index, strategy_name) pairs for each variant slot.
    # ------------------------------------------------------------------
    variant_count: int = brief.variant_count

    # Use the LLM-inclusive rotation only when an LLMClient is wired in;
    # otherwise fall back to the deterministic-only rotation so legacy
    # call sites (e.g. the LangGraph node) keep working unchanged.
    rotation = (
        _STRATEGY_ROTATION_FULL if llm_client is not None else _STRATEGY_ROTATION_DETERMINISTIC
    )

    def _pick_seed(variant_idx: int) -> SeedAttack:
        return seeds[variant_idx % len(seeds)]

    def _pick_strategy(variant_idx: int) -> MutationStrategyName:
        return rotation[variant_idx % len(rotation)]

    def _rng_seed_for(variant_idx: int) -> int:
        return int.from_bytes(brief_id.bytes[:4], "big") ^ variant_idx

    # ------------------------------------------------------------------
    # Pre-batch LLM variants: group every variant slot whose strategy is
    # "llm" by its assigned seed, then issue one batched amutate() call per
    # group. This replaces the previous per-variant amutate(count=1, ...)
    # loop (~$0.02/variant on Llama 3.3 70B) with a single completion that
    # returns N variants (~$0.001-0.005/variant).
    # ------------------------------------------------------------------
    llm_variants_by_slot: dict[int, Variant] = {}
    if llm_client is not None:
        # Collect (variant_idx, seed) for every LLM slot.
        llm_slots: list[tuple[int, SeedAttack]] = [
            (i, _pick_seed(i)) for i in range(variant_count) if _pick_strategy(i) == "llm"
        ]
        # Group by seed_id; preserve slot order so variant_index assignment is stable.
        slots_by_seed: dict[str, list[int]] = {}
        seeds_by_id: dict[str, SeedAttack] = {}
        for slot_idx, slot_seed in llm_slots:
            slots_by_seed.setdefault(slot_seed.seed_id, []).append(slot_idx)
            seeds_by_id[slot_seed.seed_id] = slot_seed

        llm_strategy = get_strategy("llm", llm_client=llm_client, campaign_id=campaign.id)
        for seed_id, slot_indices in slots_by_seed.items():
            seed_for_group = seeds_by_id[seed_id]
            # Use the rng_seed of the first slot in this group as the bucket seed.
            # Individual slots keep their own variant_idx-derived rng_seed in
            # attack_metadata below.
            group_rng_seed = _rng_seed_for(slot_indices[0])
            assert isinstance(llm_strategy, AsyncMutationStrategy)
            produced: list[Variant] = await llm_strategy.amutate(
                seed_for_group,
                count=len(slot_indices),
                rng_seed=group_rng_seed,
            )
            for slot_pos, slot_idx in enumerate(slot_indices):
                if slot_pos < len(produced):
                    llm_variants_by_slot[slot_idx] = produced[slot_pos]

    # ------------------------------------------------------------------
    # Step 4: Execute variants against the target.
    # ------------------------------------------------------------------
    completed_count = 0
    awaiting_judgment_ids: list[str] = []
    halted_reason: str | None = None

    async with TargetClient(settings, rate_limiter) as client:
        await client.authenticate()

        for variant_idx in range(variant_count):
            # ------------------------------------------------------------------
            # In-loop halt guard: between attack N and N+1, check whether the
            # operator flipped the campaign row to HALTED. This is a graceful
            # exit — the previous attack is already persisted and its Judge
            # job has been enqueued. No torn writes.
            # ------------------------------------------------------------------
            if variant_idx > 0:
                async with session_factory() as halt_session:
                    fresh = await campaign_repo.get(halt_session, campaign.id)
                if fresh is not None and fresh.status == CampaignStatus.HALTED:
                    log_event(
                        "red_team_executor_halted",
                        brief_id=str(brief_id),
                        campaign_id=str(campaign.id),
                        variant_index=variant_idx,
                        completed_attack_count=completed_count,
                        outcome="halted",
                    )
                    halted_reason = "operator_halt"
                    break

            seed = _pick_seed(variant_idx)
            strategy_name = _pick_strategy(variant_idx)
            rng_seed = _rng_seed_for(variant_idx)

            # LLM-strategy slots were pre-batched above into one call per
            # (seed_id) group. Look up the produced variant for this slot
            # rather than issuing another Llama completion here.
            if strategy_name == "llm":
                variant_opt = llm_variants_by_slot.get(variant_idx)
                if variant_opt is None:
                    log_event(
                        "red_team_variant_skipped",
                        brief_id=str(brief_id),
                        variant_index=variant_idx,
                        strategy=strategy_name,
                        reason="llm_batch_returned_short",
                    )
                    continue
                variant = variant_opt
            else:
                strategy = get_strategy(
                    strategy_name,
                    llm_client=llm_client,
                    campaign_id=campaign.id,
                )
                # Deterministic strategies are exactly reproducible.
                if isinstance(strategy, AsyncMutationStrategy):
                    variants: list[Variant] = await strategy.amutate(
                        seed, count=1, rng_seed=rng_seed
                    )
                else:
                    variants = strategy.mutate(seed, count=1, rng_seed=rng_seed)
                if not variants:
                    log_event(
                        "red_team_variant_skipped",
                        brief_id=str(brief_id),
                        variant_index=variant_idx,
                        strategy=strategy_name,
                        reason="mutate_returned_empty",
                    )
                    continue
                variant = variants[0]

            # Build metadata dict for DB storage.
            meta: dict[str, str | int | bool] = {
                "variant_index": variant_idx,
                "transform": str(variant.attack_metadata.get("transform", "unknown")),
            }
            for k, v in variant.attack_metadata.items():
                if k != "transform" and isinstance(v, (str, int, bool)):
                    meta[k] = v

            attack_input_str = _serialize_attack_input(variant.attack_input)

            # ------------------------------------------------------------------
            # Create attack row (idempotent — skips if variant_index exists).
            # ------------------------------------------------------------------
            async with session_factory() as session:
                attack = await attack_repo.create_pending(
                    session,
                    campaign_id=campaign.id,
                    brief_id=brief_id,
                    category=variant.category,
                    subcategory=variant.subcategory,
                    mutation_strategy=strategy_name,
                    seed_used=variant.seed_id,
                    attack_input=attack_input_str,
                    attack_metadata=meta,
                )
                await session.commit()

            # Idempotency gate for per-attack Judge enqueue (TODO #59):
            # If the row came back in any status other than pending_execution,
            # it was already fired on a prior run. Skip both fire AND enqueue
            # to avoid double-judging.
            if attack.status != AttackStatus.PENDING_EXECUTION:
                log_event(
                    "red_team_attack_skipped_already_executed",
                    brief_id=str(brief_id),
                    attack_id=str(attack.id),
                    variant_index=variant_idx,
                    existing_status=attack.status.value,
                    outcome="idempotent_skip",
                )
                continue

            # ------------------------------------------------------------------
            # Fire query (rate limiter enforced inside TargetClient.fire_query).
            # ------------------------------------------------------------------
            try:
                if isinstance(variant.attack_input, list):
                    # Multi-turn: use fire_multi_turn; store the last response.
                    responses = await client.fire_multi_turn(
                        turns=variant.attack_input,
                        attack_id=attack.id,
                        campaign_id=campaign.id,
                        patient_ids=_SYNTHETIC_PATIENT_IDS,
                    )
                    target_resp = responses[-1] if responses else None
                else:
                    target_resp = await client.fire_query(
                        message=variant.attack_input,
                        attack_id=attack.id,
                        campaign_id=campaign.id,
                        patient_ids=_SYNTHETIC_PATIENT_IDS,
                    )

            except CampaignAttackCapReached:
                log_event(
                    "red_team_campaign_cap_reached",
                    brief_id=str(brief_id),
                    campaign_id=str(campaign.id),
                    variant_index=variant_idx,
                    outcome="halted",
                )
                async with session_factory() as session:
                    await campaign_repo.update_status(
                        session,
                        campaign_id=campaign.id,
                        status=CampaignStatus.BUDGET_EXHAUSTED,
                        expected_version_id=campaign.version_id,
                    )
                    await session.commit()
                halted_reason = "campaign_attack_cap_reached"
                break

            except TargetUnavailableError as exc:
                log_event(
                    "red_team_target_unavailable",
                    brief_id=str(brief_id),
                    attack_id=str(attack.id),
                    variant_index=variant_idx,
                    error_class=type(exc).__name__,
                    outcome="target_unavailable",
                )
                async with session_factory() as session:
                    await attack_repo.mark_target_unavailable(
                        session,
                        attack_id=attack.id,
                        error=type(exc).__name__,
                    )
                    await session.commit()
                continue

            # ------------------------------------------------------------------
            # Persist target response.
            # ------------------------------------------------------------------
            if target_resp is not None:
                async with session_factory() as session:
                    await attack_repo.mark_awaiting_judgment(
                        session,
                        attack_id=attack.id,
                        target_response=target_resp.response_body,
                        target_response_status=target_resp.status_code,
                        target_response_time_ms=target_resp.response_time_ms,
                    )
                    await session.commit()
                completed_count += 1
                awaiting_judgment_ids.append(str(attack.id))

                # Per-attack Judge enqueue (TODO #59 fix): if the executor
                # later crashes or the arq job_timeout fires, every attack
                # that already landed in awaiting_judgment has its Judge
                # job sitting in Redis — no manual recovery required.
                # arq dedups on _job_id="judge:{attack_id}", so a retried
                # executor that somehow re-fires would still not double-enqueue.
                if judge_enqueuer is not None:
                    assert request_id is not None  # narrowed by the precondition
                    await judge_enqueuer(attack.id, request_id)
                    log_event(
                        "red_team_judge_enqueued",
                        brief_id=str(brief_id),
                        attack_id=str(attack.id),
                        variant_index=variant_idx,
                        outcome="success",
                    )

    # ------------------------------------------------------------------
    # Step 5: Mark brief and campaign completed (unless halted).
    # ------------------------------------------------------------------
    if halted_reason is None:
        async with session_factory() as session:
            await session.execute(
                __import__("sqlalchemy").text(
                    "UPDATE campaign_briefs SET status = 'completed'"
                    " WHERE id = :id AND status != 'completed'"
                ),
                {"id": str(brief_id)},
            )
            # Reload campaign for current version_id before update.
            refreshed = await campaign_repo.get(session, campaign.id)
            if refreshed is not None:
                await campaign_repo.update_status(
                    session,
                    campaign_id=campaign.id,
                    status=CampaignStatus.COMPLETED,
                    expected_version_id=refreshed.version_id,
                )
            await session.commit()

    log_event(
        "campaign_completed",
        brief_id=str(brief_id),
        campaign_id=str(campaign.id),
        completed_attack_count=completed_count,
        halted_reason=halted_reason,
        outcome="success" if halted_reason is None else "halted",
    )

    return {
        "completed_attack_count": completed_count,
        "halted_reason": halted_reason,
        "awaiting_judgment_attack_ids": awaiting_judgment_ids,
    }
