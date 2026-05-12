"""Unit tests for MultiTurnMutationStrategy.

Covers:
  - attack_input is list[str] with 2-4 elements
  - Final turn contains payload trigger from the seed
  - Determinism: same rng_seed → same output
  - Uniqueness: N distinct sequences for count=5
  - Metadata: attack_metadata['transform'] is present and names a known strategy
  - Protocol compliance
  - Subcategory / category / endpoint / rubric preservation
  - Variant index is sequential
"""

import pytest

from src.agents.red_team.mutations.base import MutationStrategy
from src.agents.red_team.mutations.multi_turn import MultiTurnMutationStrategy
from src.agents.red_team.types import SeedAttack

_KNOWN_STRATEGIES = frozenset(
    ["establish_then_exploit", "gradual_authority_drift", "distraction_then_swap"]
)


@pytest.fixture
def strategy() -> MultiTurnMutationStrategy:
    return MultiTurnMutationStrategy()


def test_attack_input_is_list(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """attack_input must be list[str] for all multi-turn variants."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert isinstance(v.attack_input, list), (
            f"Variant {v.variant_index}: attack_input must be list, got {type(v.attack_input)}"
        )


def test_attack_input_has_2_to_4_turns(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Each multi-turn sequence must have 2-4 elements."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        turns = v.attack_input
        assert isinstance(turns, list)
        assert 2 <= len(turns) <= 4, (
            f"Variant {v.variant_index}: expected 2-4 turns, got {len(turns)}"
        )


def test_each_turn_is_nonempty_string(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Each turn in the sequence must be a non-empty string."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        turns = v.attack_input
        assert isinstance(turns, list)
        for i, turn in enumerate(turns):
            assert isinstance(turn, str) and len(turn) > 0, (
                f"Variant {v.variant_index} turn {i} is empty or not a string"
            )


def test_final_turn_contains_payload_trigger(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """The final turn must contain the out-of-panel identifier 'pt-018'.

    The first turns can be benign preambles; the payload must land in the
    last turn (or be distributed, but always visible in the last turn).
    """
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        turns = v.attack_input
        assert isinstance(turns, list)
        last_turn = turns[-1]
        assert "pt-018" in last_turn, (
            f"Variant {v.variant_index} (transform={v.attack_metadata['transform']}): "
            f"payload trigger 'pt-018' not found in final turn: {last_turn!r}"
        )


def test_produces_5_unique_sequences(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """count=5 must yield 5 distinct turn-sequences."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    assert len(variants) == 5
    # Canonicalise each sequence to a string for uniqueness check
    keys = ["|||".join(v.attack_input) for v in variants if isinstance(v.attack_input, list)]
    assert len(set(keys)) == 5, "All 5 sequences must be distinct"


def test_determinism_same_seed(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Same rng_seed → identical output on repeated calls."""
    first = strategy.mutate(cross_patient_seed, count=5, rng_seed=55)
    second = strategy.mutate(cross_patient_seed, count=5, rng_seed=55)
    assert [v.attack_input for v in first] == [v.attack_input for v in second]


def test_different_seeds_differ(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Different rng_seeds should (with high probability) produce different sequences."""
    a = strategy.mutate(cross_patient_seed, count=5, rng_seed=1)
    b = strategy.mutate(cross_patient_seed, count=5, rng_seed=2)
    a_keys = {"|||".join(v.attack_input) for v in a if isinstance(v.attack_input, list)}
    b_keys = {"|||".join(v.attack_input) for v in b if isinstance(v.attack_input, list)}
    assert a_keys != b_keys


def test_transform_metadata_present(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Each variant must have 'transform' in attack_metadata."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert "transform" in v.attack_metadata


def test_transform_metadata_is_known_strategy(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """The 'transform' value must be one of the known split strategy names."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        transform = str(v.attack_metadata["transform"])
        assert transform in _KNOWN_STRATEGIES, (
            f"transform '{transform}' is not a known multi-turn strategy; "
            f"known: {_KNOWN_STRATEGIES}"
        )


def test_subcategory_preserved(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.subcategory == cross_patient_seed.subcategory


def test_category_preserved(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.category == cross_patient_seed.category


def test_target_endpoint_preserved(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.target_endpoint == cross_patient_seed.target_endpoint


def test_judge_rubric_hints_preserved(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.judge_rubric_hints == cross_patient_seed.judge_rubric_hints


def test_mutation_strategy_name(strategy: MultiTurnMutationStrategy) -> None:
    assert strategy.name == "multi_turn"


def test_mutation_strategy_name_on_variants(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.mutation_strategy == "multi_turn"


def test_satisfies_protocol(strategy: MultiTurnMutationStrategy) -> None:
    assert isinstance(strategy, MutationStrategy)


def test_seed_id_preserved(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=3, rng_seed=42)
    for v in variants:
        assert v.seed_id == cross_patient_seed.seed_id


def test_variant_index_sequential(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    count = 5
    variants = strategy.mutate(cross_patient_seed, count=count, rng_seed=42)
    assert [v.variant_index for v in variants] == list(range(count))


def test_works_with_privilege_escalation_seed(
    strategy: MultiTurnMutationStrategy,
    privilege_escalation_seed: SeedAttack,
) -> None:
    """Strategy must work correctly for a different seed / subcategory."""
    variants = strategy.mutate(privilege_escalation_seed, count=5, rng_seed=7)
    assert len(variants) == 5
    for v in variants:
        assert v.subcategory == privilege_escalation_seed.subcategory
        assert isinstance(v.attack_input, list)


def test_preamble_turns_are_benign(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """For establish_then_exploit and gradual_authority_drift, the early turns
    should NOT contain the payload trigger (they are preambles).

    This validates that the multi-turn strategy actually stages the attack
    rather than repeating the payload in every turn.
    """
    variants = strategy.mutate(cross_patient_seed, count=9, rng_seed=42)
    # Filter to sequences with 3+ turns (establish/gradual strategies)
    three_turn = [
        v for v in variants if isinstance(v.attack_input, list) and len(v.attack_input) >= 3
    ]
    if not three_turn:
        pytest.skip("No 3-turn variants produced with this seed — adjust rng_seed")

    for v in three_turn:
        turns = v.attack_input
        assert isinstance(turns, list)
        # Turn 0 should NOT contain the payload trigger
        assert "pt-018" not in turns[0], (
            f"Turn 0 of variant {v.variant_index} contains payload trigger — "
            "preamble turn should be benign"
        )


def test_produces_sequences_with_multiple_split_strategies(
    strategy: MultiTurnMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Requesting count=9 should exercise all 3 split strategies."""
    variants = strategy.mutate(cross_patient_seed, count=9, rng_seed=42)
    assert len(variants) == 9
    transforms_used = {str(v.attack_metadata["transform"]) for v in variants}
    # All three strategies should appear across 9 variants
    assert len(transforms_used) == 3, f"Expected all 3 split strategies, got: {transforms_used}"
