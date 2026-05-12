"""Unit tests for StructuralMutationStrategy.

Covers:
  - Uniqueness: N distinct framing strings for count=5 and count=7
  - Determinism: same rng_seed → same output
  - Framing tag: attack_metadata['transform'] is present and a known framing
  - Payload preservation: the original message_template content appears inside
    every structural envelope
  - Subcategory / category / endpoint / rubric preservation
  - Protocol compliance
  - Counts > number of framings (7) produce additional unique strings
"""

import pytest

from src.agents.red_team.mutations.base import MutationStrategy
from src.agents.red_team.mutations.structural import (
    _FRAMING_NAMES,
    StructuralMutationStrategy,
)
from src.agents.red_team.types import SeedAttack


@pytest.fixture
def strategy() -> StructuralMutationStrategy:
    return StructuralMutationStrategy()


def test_produces_5_unique_variants(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """count=5 must yield exactly 5 distinct attack_input strings."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    assert len(variants) == 5
    texts = [v.attack_input for v in variants]
    assert len(set(texts)) == 5


def test_produces_7_unique_variants(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """count=7 (= number of framings) must yield 7 distinct strings."""
    variants = strategy.mutate(cross_patient_seed, count=7, rng_seed=42)
    assert len(variants) == 7
    texts = [v.attack_input for v in variants]
    assert len(set(texts)) == 7


def test_produces_10_unique_variants_beyond_framing_count(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """count=10 (> 7 framings) must still yield 10 distinct strings."""
    variants = strategy.mutate(cross_patient_seed, count=10, rng_seed=42)
    assert len(variants) == 10
    texts = [v.attack_input for v in variants]
    assert len(set(texts)) == 10


def test_determinism_same_seed(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Same rng_seed → identical output on repeated calls."""
    first = strategy.mutate(cross_patient_seed, count=6, rng_seed=77)
    second = strategy.mutate(cross_patient_seed, count=6, rng_seed=77)
    assert [v.attack_input for v in first] == [v.attack_input for v in second]


def test_different_seeds_differ(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Different rng_seeds must produce different framing orders."""
    a = strategy.mutate(cross_patient_seed, count=5, rng_seed=1)
    b = strategy.mutate(cross_patient_seed, count=5, rng_seed=2)
    assert [v.attack_input for v in a] != [v.attack_input for v in b]


def test_framing_tag_present(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Each variant must have 'transform' in attack_metadata."""
    variants = strategy.mutate(cross_patient_seed, count=7, rng_seed=42)
    for v in variants:
        assert "transform" in v.attack_metadata


def test_framing_tag_is_known_framing(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """For the first 7 variants, the transform must be a known framing name
    (or a known framing name with a '+qualifier_N' suffix for overflow)."""
    variants = strategy.mutate(cross_patient_seed, count=7, rng_seed=42)
    for v in variants:
        transform = str(v.attack_metadata["transform"])
        # Either a plain framing name or 'framing_name+qualifier_N'
        base = transform.split("+")[0]
        assert base in _FRAMING_NAMES, (
            f"transform '{transform}' base '{base}' not in known framings: {_FRAMING_NAMES}"
        )


def test_payload_preserved_in_envelope(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """The original message_template text (or a key fragment) must appear in
    every structural envelope.

    We check that 'pt-018' (the out-of-panel identifier) is present in all
    variants. This guards against framings that silently drop the payload.
    """
    variants = strategy.mutate(cross_patient_seed, count=7, rng_seed=42)
    for v in variants:
        text = v.attack_input
        assert isinstance(text, str), "Structural variants must have str attack_input"
        assert "pt-018" in text, (
            f"Variant {v.variant_index} (transform={v.attack_metadata['transform']}) "
            f"dropped 'pt-018' from attack_input"
        )


def test_subcategory_preserved(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.subcategory == cross_patient_seed.subcategory


def test_category_preserved(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.category == cross_patient_seed.category


def test_target_endpoint_preserved(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.target_endpoint == cross_patient_seed.target_endpoint


def test_judge_rubric_hints_preserved(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.judge_rubric_hints == cross_patient_seed.judge_rubric_hints


def test_mutation_strategy_name(strategy: StructuralMutationStrategy) -> None:
    assert strategy.name == "structural"


def test_mutation_strategy_name_on_variants(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert v.mutation_strategy == "structural"


def test_satisfies_protocol(strategy: StructuralMutationStrategy) -> None:
    assert isinstance(strategy, MutationStrategy)


def test_attack_input_is_str(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    """Structural variants are single-turn — attack_input must be str."""
    variants = strategy.mutate(cross_patient_seed, count=5, rng_seed=42)
    for v in variants:
        assert isinstance(v.attack_input, str)


def test_variant_index_sequential(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    count = 6
    variants = strategy.mutate(cross_patient_seed, count=count, rng_seed=42)
    assert [v.variant_index for v in variants] == list(range(count))


def test_seed_id_preserved(
    strategy: StructuralMutationStrategy,
    cross_patient_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(cross_patient_seed, count=3, rng_seed=42)
    for v in variants:
        assert v.seed_id == cross_patient_seed.seed_id


def test_works_with_privilege_seed(
    strategy: StructuralMutationStrategy,
    privilege_escalation_seed: SeedAttack,
) -> None:
    variants = strategy.mutate(privilege_escalation_seed, count=5, rng_seed=13)
    assert len(variants) == 5
    for v in variants:
        assert v.subcategory == privilege_escalation_seed.subcategory
        assert isinstance(v.attack_input, str)
