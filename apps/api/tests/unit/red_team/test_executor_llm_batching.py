"""Unit test for the executor's LLM batching dispatch.

The executor previously called LLMMutationStrategy.amutate(count=1, ...) once
per LLM-rotation slot — wasteful (one Llama completion per variant).

After the batching refactor, the executor pre-computes every LLM-strategy
slot, groups them by seed_id, and issues ONE amutate(count=K, ...) per group.

This test exercises ONLY the pre-batch dispatch code path inside
run_executor. It mocks everything heavier (Postgres, TargetClient,
seed_loader) and observes the LLMMutationStrategy.amutate call count.

Expected result for a 10-variant brief (rotation = 4 strategies; ~2-3 slots
land on "llm"), all sharing one seed file → exactly ONE amutate call.
With multiple seeds, ≤ 2 calls (one per seed_id group).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.agents.red_team.types import SeedAttack, Variant


def _make_seed(seed_id: str = "seed-A") -> SeedAttack:
    return SeedAttack(
        seed_id=seed_id,
        category="data_exfiltration",
        subcategory="data_exfiltration/cross_patient_leakage",
        message_template="Summarize patient pt-018",
        target_endpoint="POST /agent/query",
        framework_mappings={"owasp_llm": "LLM02:2025"},
        expected_safe_behavior="Should refuse",
        judge_rubric_hints={"success_criteria": "X"},
        tags=[],
    )


def _make_variant(seed_id: str, idx: int) -> Variant:
    return Variant(
        seed_id=seed_id,
        variant_index=idx,
        mutation_strategy="llm",
        category="data_exfiltration",
        subcategory="data_exfiltration/cross_patient_leakage",
        attack_input=f"llm-variant-{idx}",
        attack_metadata={"transform": "llm:llama-3.3-70b", "transform_label": "x"},
        judge_rubric_hints={"success_criteria": "X"},
        target_endpoint="POST /agent/query",
    )


@pytest.mark.asyncio
async def test_executor_batches_llm_variants_into_one_call_per_seed_group() -> None:
    """A 10-variant brief over a single seed file → exactly ONE Llama call
    for the LLM-rotation slots (not 2-3 calls, one per slot).

    With variant_count=10 and rotation=[lexical, structural, multi_turn, llm],
    the LLM slots fall at variant_idx 3 and 7 (two slots). Both map to the
    same seed (only one seed in the fixture), so they MUST batch into a
    single amutate(count=2, ...) call — not two amutate(count=1) calls.
    """
    from src.agents.red_team import executor as executor_mod

    brief_id = uuid4()
    campaign_id = uuid4()

    # ------- Mock brief + campaign so step 1 passes (status != completed).
    brief = MagicMock()
    brief.campaign_id = campaign_id
    brief.status = "in_progress"  # not COMPLETED
    brief.target_subcategory = "data_exfiltration/cross_patient_leakage"
    brief.variant_count = 10

    campaign = MagicMock()
    campaign.id = campaign_id
    campaign.version_id = 1
    campaign.status = "in_progress"

    campaign_repo_mock = MagicMock()
    campaign_repo_mock.get_brief = AsyncMock(return_value=brief)
    campaign_repo_mock.get = AsyncMock(return_value=campaign)
    campaign_repo_mock.update_status = AsyncMock()

    # ------- Mock attack repo so create_pending returns a fresh attack with
    # status PENDING_EXECUTION (so the executor proceeds to fire_query).
    attack_repo_mock = MagicMock()

    from src.domain.attack import AttackStatus

    def _make_attack_row(*args: Any, **kwargs: Any) -> MagicMock:
        a = MagicMock()
        a.id = uuid4()
        a.status = AttackStatus.PENDING_EXECUTION
        return a

    attack_repo_mock.create_pending = AsyncMock(side_effect=_make_attack_row)
    attack_repo_mock.mark_awaiting_judgment = AsyncMock()
    attack_repo_mock.mark_target_unavailable = AsyncMock()

    # ------- session_factory is an async context manager yielding a mock session.
    session_mock = MagicMock()
    session_mock.commit = AsyncMock()
    session_mock.execute = AsyncMock(return_value=MagicMock(first=lambda: (0,)))

    class _SessionCM:
        async def __aenter__(self) -> Any:
            return session_mock

        async def __aexit__(self, *args: Any) -> None:
            return None

    session_factory = MagicMock(side_effect=lambda: _SessionCM())

    # ------- TargetClient is an async context manager; fire_query returns a
    # fake response object so mark_awaiting_judgment is called.
    target_resp = MagicMock()
    target_resp.response_body = "{}"
    target_resp.status_code = 200
    target_resp.response_time_ms = 12.0

    target_client_mock = MagicMock()
    target_client_mock.authenticate = AsyncMock()
    target_client_mock.fire_query = AsyncMock(return_value=target_resp)
    target_client_mock.fire_multi_turn = AsyncMock(return_value=[target_resp])

    class _TargetClientCM:
        async def __aenter__(self) -> Any:
            return target_client_mock

        async def __aexit__(self, *args: Any) -> None:
            return None

    # ------- LLM strategy spy: counts amutate calls. Returns enough variants
    # for whatever count is requested.
    llm_strategy_spy = MagicMock()
    llm_strategy_spy.name = "llm"

    async def _spy_amutate(seed: SeedAttack, count: int, rng_seed: int) -> list[Variant]:
        return [_make_variant(seed.seed_id, i) for i in range(count)]

    llm_strategy_spy.amutate = AsyncMock(side_effect=_spy_amutate)

    # Make isinstance(strategy, AsyncMutationStrategy) succeed for the spy.
    from src.agents.red_team.mutations.base import AsyncMutationStrategy

    AsyncMutationStrategy.register(type(llm_strategy_spy))  # type: ignore[attr-defined]

    # Deterministic strategies: pass-through stubs.
    def _det_mutate(seed: SeedAttack, count: int, rng_seed: int) -> list[Variant]:
        return [_make_variant(seed.seed_id, 0)]

    det_strategy = MagicMock()
    det_strategy.mutate = _det_mutate

    def _fake_get_strategy(name: str, **_: Any) -> Any:
        return llm_strategy_spy if name == "llm" else det_strategy

    rate_limiter_mock = MagicMock()

    settings_mock = MagicMock()

    llm_client_mock = MagicMock()

    # ------- Patch all collaborators on the executor module.
    with (
        patch.object(executor_mod, "CampaignRepository", return_value=campaign_repo_mock),
        patch.object(executor_mod, "AttackRepository", return_value=attack_repo_mock),
        patch.object(executor_mod, "get_strategy", side_effect=_fake_get_strategy),
        patch.object(executor_mod, "TargetClient", return_value=_TargetClientCM()),
        patch.object(
            executor_mod,
            "load_seeds_for_subcategory",
            return_value=[_make_seed("seed-A")],
        ),
        # Bypass BriefStatus comparison (brief.status != COMPLETED already true)
    ):
        from src.domain.campaign import BriefStatus

        brief.status = BriefStatus.IN_PROGRESS

        result = await executor_mod.run_executor(
            brief_id=brief_id,
            session_factory=session_factory,
            settings=settings_mock,
            rate_limiter=rate_limiter_mock,
            llm_client=llm_client_mock,
        )

    # ----- The core assertion: ONE amutate call for the whole brief,
    # not one per LLM-rotation slot.
    assert llm_strategy_spy.amutate.call_count == 1, (
        f"Expected 1 batched LLM call, got {llm_strategy_spy.amutate.call_count}. "
        "Regression: executor is back to per-variant Llama calls."
    )
    # And the single call requested >= 2 variants (two LLM slots in a 10-variant
    # rotation: indices 3 and 7).
    call_kwargs = llm_strategy_spy.amutate.call_args.kwargs
    assert call_kwargs["count"] >= 2

    assert isinstance(result, dict)
    assert result["completed_attack_count"] >= 1
