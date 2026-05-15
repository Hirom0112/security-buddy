"""Protocol definition for mutation strategies.

All concrete strategies must satisfy MutationStrategy. The Protocol is
structural (duck-typed), so no inheritance is required — just match the
attribute and method signatures.

Import boundary: this module is part of src.agents.red_team and may only
import from src.domain, src.observability, and src.agents.red_team itself.
It must NOT import from src.agents.judge, src.agents.orchestrator,
src.agents.documentation, or src.agents.patch.
"""

from typing import Protocol, runtime_checkable

from src.agents.red_team.types import MutationStrategyName, SeedAttack, Variant


@runtime_checkable
class MutationStrategy(Protocol):
    """Pure function shape — takes a seed, returns N variants.

    Implementations must be:
    - Deterministic: same (seed, count, rng_seed) → same list[Variant]
    - Pure: no I/O, no global state, no subprocess
    - Safe: never eval/exec any payload content

    The `name` attribute identifies which strategy produced a given batch;
    it is written to Variant.mutation_strategy and to attack rows in Postgres.
    """

    name: MutationStrategyName

    def mutate(self, seed: SeedAttack, count: int, rng_seed: int) -> list[Variant]:
        """Generate up to `count` distinct variants of `seed`.

        Args:
            seed: The base SeedAttack to mutate.
            count: Desired number of distinct variants. The implementation
                   must return at least ceil(count / 2) unless the seed
                   is completely unmutable (e.g., a one-word template).
            rng_seed: Determinism seed. Same rng_seed → same output.

        Returns:
            A list of Variant objects. All variants must:
            - Have attack_input that differs from every other variant in
              the batch (no duplicate strings).
            - Preserve subcategory, category, target_endpoint, and
              judge_rubric_hints from the source seed.
            - Include 'transform' key in attack_metadata.
        """
        ...


@runtime_checkable
class AsyncMutationStrategy(Protocol):
    """Async mutation strategy — same contract as MutationStrategy, but I/O bound.

    For strategies whose body performs network I/O (e.g. an LLM call) and so
    cannot be implemented as a pure sync function. The executor dispatches on
    isinstance(strategy, AsyncMutationStrategy) and awaits amutate() instead
    of calling mutate().

    A concrete strategy satisfies exactly one of MutationStrategy or
    AsyncMutationStrategy — never both. Determinism semantics still apply
    insofar as the rng_seed is propagated (e.g. passed as a variation hint
    into a prompt), but exact reproducibility is not guaranteed when the
    underlying model is non-deterministic.
    """

    name: MutationStrategyName

    async def amutate(self, seed: SeedAttack, count: int, rng_seed: int) -> list[Variant]:
        """Async analogue of MutationStrategy.mutate. See that docstring."""
        ...
