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
from uuid import UUID  # noqa: TC003

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

from src.agents.red_team.mutations.registry import get_strategy
from src.agents.red_team.rate_limit import CampaignAttackCapReached, RateLimiter
from src.agents.red_team.seed_loader import load_seeds_for_subcategory
from src.agents.red_team.target_client import TargetClient, TargetUnavailableError
from src.agents.red_team.types import MutationStrategyName, SeedAttack, Variant  # noqa: TC001
from src.domain.campaign import BriefStatus, CampaignStatus
from src.observability.events import log_event
from src.repositories.attacks import AttackRepository
from src.repositories.campaigns import CampaignRepository
from src.settings import Settings  # noqa: TC001

# Ordered rotation of mutation strategies applied round-robin across variants.
_STRATEGY_ROTATION: list[MutationStrategyName] = ["lexical", "structural", "multi_turn"]

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
) -> dict[str, object]:
    """Execute the Red Team loop for a single campaign brief.

    Args:
        brief_id: UUID of the campaign_brief row to execute.
        session_factory: SQLAlchemy async session factory.
        settings: Application settings (target URLs, credentials).
        rate_limiter: Shared outbound rate limiter (enforced before every
            TargetClient.fire_query call).

    Returns:
        A dict with:
          - completed_attack_count: int
          - halted_reason: str | None (None when all variants completed normally)

    The function is idempotent: calling it twice for the same brief_id
    returns early on the second call without any duplicate writes.
    """
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

    def _pick_seed(variant_idx: int) -> SeedAttack:
        return seeds[variant_idx % len(seeds)]

    def _pick_strategy(variant_idx: int) -> MutationStrategyName:
        return _STRATEGY_ROTATION[variant_idx % len(_STRATEGY_ROTATION)]

    # ------------------------------------------------------------------
    # Step 4: Execute variants against the target.
    # ------------------------------------------------------------------
    completed_count = 0
    halted_reason: str | None = None

    async with TargetClient(settings, rate_limiter) as client:
        await client.authenticate()

        for variant_idx in range(variant_count):
            seed = _pick_seed(variant_idx)
            strategy_name = _pick_strategy(variant_idx)
            strategy = get_strategy(strategy_name)

            # Generate one variant deterministically.
            # rng_seed combines brief_id bytes + variant_idx for reproducibility.
            rng_seed = int.from_bytes(brief_id.bytes[:4], "big") ^ variant_idx
            variants: list[Variant] = strategy.mutate(seed, count=1, rng_seed=rng_seed)
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
    }
