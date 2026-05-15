"""Unit tests for LLMMutationStrategy.

Covers:
  - Valid JSON response → variants returned with correct metadata
  - Trimming: returns exactly `count` even when LLM over-produces
  - Refusal / non-JSON → returns [] and logs red_team_llm_parse_failed
  - Schema violation → returns []
  - httpx.TimeoutException → returns [], no exception leak, log fires
  - LLM call tagged with agent="red_team" and campaign_id
  - Variant attack_metadata contains rng_seed and transform_label
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import UUID

import httpx
import pytest

from src.agents.red_team.mutations.base import AsyncMutationStrategy
from src.agents.red_team.mutations.llm import LLMMutationStrategy
from src.agents.red_team.types import SeedAttack  # noqa: TC001
from src.llm_client.types import Completion, TokenUsage


def _make_completion(content: str) -> Completion:
    return Completion(
        model=LLMMutationStrategy.MODEL,
        content=content,
        usage=TokenUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
        cost_usd=0.001,
        duration_ms=42.0,
        prompt_hash="a" * 64,
        completion_hash="b" * 64,
    )


@pytest.fixture
def llm_client() -> Any:
    """A bare LLMClient stub. We only patch its .complete method per-test."""

    class _Stub:
        complete = AsyncMock()

    return _Stub()


@pytest.fixture
def strategy(llm_client: Any) -> LLMMutationStrategy:
    return LLMMutationStrategy(llm_client=llm_client)


def test_satisfies_async_protocol(strategy: LLMMutationStrategy) -> None:
    assert isinstance(strategy, AsyncMutationStrategy)
    assert strategy.name == "llm"


@pytest.mark.asyncio
async def test_amutate_parses_valid_json_returns_variants(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    payload = json.dumps(
        {
            "variants": [
                {"attack_input": "variant one text", "transform_label": "persona_injection"},
                {"attack_input": "variant two text", "transform_label": "encoded_payload"},
                {"attack_input": "variant three text", "transform_label": "authority_spoof"},
            ]
        }
    )
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    variants = await strategy.amutate(cross_patient_seed, count=3, rng_seed=42)

    assert len(variants) == 3
    assert variants[0].mutation_strategy == "llm"
    assert variants[0].attack_input == "variant one text"
    assert variants[0].seed_id == cross_patient_seed.seed_id
    assert variants[0].category == cross_patient_seed.category
    assert variants[0].subcategory == cross_patient_seed.subcategory
    assert variants[0].target_endpoint == cross_patient_seed.target_endpoint
    assert variants[0].judge_rubric_hints == cross_patient_seed.judge_rubric_hints
    assert variants[0].variant_index == 0
    assert variants[2].variant_index == 2


@pytest.mark.asyncio
async def test_amutate_trims_to_count(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    payload = json.dumps(
        {"variants": [{"attack_input": f"v{i}", "transform_label": "t"} for i in range(5)]}
    )
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    variants = await strategy.amutate(cross_patient_seed, count=3, rng_seed=1)
    assert len(variants) == 3


@pytest.mark.asyncio
async def test_amutate_returns_empty_on_refusal(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    llm_client.complete = AsyncMock(return_value=_make_completion("I cannot help with that."))

    with patch("src.agents.red_team.mutations.llm.log_event") as mock_log:
        variants = await strategy.amutate(cross_patient_seed, count=3, rng_seed=7)

    assert variants == []
    event_names = [call.args[0] for call in mock_log.call_args_list]
    assert "red_team_llm_parse_failed" in event_names


@pytest.mark.asyncio
async def test_amutate_returns_empty_on_schema_violation(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    # Valid JSON, missing required 'attack_input' key
    payload = json.dumps({"variants": [{"transform_label": "x"}]})
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    with patch("src.agents.red_team.mutations.llm.log_event") as mock_log:
        variants = await strategy.amutate(cross_patient_seed, count=2, rng_seed=3)

    assert variants == []
    event_names = [call.args[0] for call in mock_log.call_args_list]
    assert "red_team_llm_parse_failed" in event_names


@pytest.mark.asyncio
async def test_amutate_returns_empty_on_timeout(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    llm_client.complete = AsyncMock(side_effect=httpx.TimeoutException("slow"))

    with patch("src.agents.red_team.mutations.llm.log_event") as mock_log:
        variants = await strategy.amutate(cross_patient_seed, count=2, rng_seed=11)

    assert variants == []
    event_names = [call.args[0] for call in mock_log.call_args_list]
    assert "red_team_llm_call_failed" in event_names


@pytest.mark.asyncio
async def test_amutate_tags_llm_call_with_agent_and_campaign(
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    campaign_id = UUID("12345678-1234-5678-1234-567812345678")
    strategy = LLMMutationStrategy(llm_client=llm_client, campaign_id=campaign_id)
    payload = json.dumps({"variants": [{"attack_input": "x", "transform_label": "t"}]})
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    await strategy.amutate(cross_patient_seed, count=1, rng_seed=5)

    llm_client.complete.assert_awaited_once()
    _, kwargs = llm_client.complete.call_args
    assert kwargs["agent"] == "red_team"
    assert kwargs["campaign_id"] == campaign_id
    assert kwargs["model"] == LLMMutationStrategy.MODEL


@pytest.mark.asyncio
async def test_amutate_count_5_makes_exactly_one_llm_call(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    """count=5 (<= _BATCH_SIZE=8) MUST be a single Llama completion.

    This is the core cost-savings invariant: prior to batching, the executor
    made one Llama call per variant (~$0.02/variant). After batching, a brief
    that asks for N <= batch_size variants from the same seed must consume
    exactly one completion.
    """
    payload = json.dumps(
        {"variants": [{"attack_input": f"v{i}", "transform_label": "t"} for i in range(5)]}
    )
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    variants = await strategy.amutate(cross_patient_seed, count=5, rng_seed=1)

    assert len(variants) == 5
    assert llm_client.complete.call_count == 1


@pytest.mark.asyncio
async def test_amutate_count_larger_than_batch_size_chunks_calls(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    """count > _BATCH_SIZE issues ceil(count/_BATCH_SIZE) calls.

    With _BATCH_SIZE=8 and count=17, the strategy should issue 3 calls
    (8 + 8 + 1).
    """
    # Each call returns 8 variants — generous, so total > requested and the
    # collected list gets trimmed to count.
    payload = json.dumps(
        {"variants": [{"attack_input": f"v{i}", "transform_label": "t"} for i in range(8)]}
    )
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    variants = await strategy.amutate(cross_patient_seed, count=17, rng_seed=99)

    assert llm_client.complete.call_count == 3
    # Strategy collected min(3 * 8, 17) = 17 variants total.
    assert len(variants) == 17


@pytest.mark.asyncio
async def test_amutate_partial_batch_falls_through_and_logs(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    """When the LLM returns fewer variants than requested, amutate returns
    what it got AND emits red_team_llm_partial_batch (NOT a silent retry).
    """
    # Request 5, but LLM only returns 2.
    payload = json.dumps(
        {
            "variants": [
                {"attack_input": "v0", "transform_label": "t"},
                {"attack_input": "v1", "transform_label": "t"},
            ]
        }
    )
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    with patch("src.agents.red_team.mutations.llm.log_event") as mock_log:
        variants = await strategy.amutate(cross_patient_seed, count=5, rng_seed=7)

    assert len(variants) == 2  # what we got, no padding
    # Exactly one call — no silent retry on short batch.
    assert llm_client.complete.call_count == 1
    event_names = [call.args[0] for call in mock_log.call_args_list]
    assert "red_team_llm_partial_batch" in event_names
    # And the partial event records requested vs returned.
    partial_call = next(
        c for c in mock_log.call_args_list if c.args[0] == "red_team_llm_partial_batch"
    )
    assert partial_call.kwargs["requested"] == 5
    assert partial_call.kwargs["returned"] == 2


@pytest.mark.asyncio
async def test_amutate_variant_metadata_records_rng_seed_and_transform_label(
    strategy: LLMMutationStrategy,
    llm_client: Any,
    cross_patient_seed: SeedAttack,
) -> None:
    payload = json.dumps(
        {"variants": [{"attack_input": "v", "transform_label": "persona_injection"}]}
    )
    llm_client.complete = AsyncMock(return_value=_make_completion(payload))

    variants = await strategy.amutate(cross_patient_seed, count=1, rng_seed=123)

    md = variants[0].attack_metadata
    assert md["transform"] == "llm:llama-3.3-70b"
    assert md["transform_label"] == "persona_injection"
    assert md["rng_seed"] == 123
