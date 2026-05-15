"""Strategy registry for Red Team mutation strategies.

Provides a single lookup point: given a MutationStrategyName, return the
corresponding strategy instance. Deterministic strategies are stateless
singletons; the LLM strategy is constructed lazily per-call because it
depends on an injected ``LLMClient``.
"""

from __future__ import annotations

from uuid import UUID  # noqa: TC003

from src.agents.red_team.mutations.base import (  # noqa: TC001
    AsyncMutationStrategy,
    MutationStrategy,
)
from src.agents.red_team.mutations.lexical import LexicalMutationStrategy
from src.agents.red_team.mutations.llm import LLMMutationStrategy
from src.agents.red_team.mutations.multi_turn import MultiTurnMutationStrategy
from src.agents.red_team.mutations.structural import StructuralMutationStrategy
from src.agents.red_team.types import MutationStrategyName  # noqa: TC001
from src.llm_client.client import LLMClient  # noqa: TC001

# Deterministic, stateless singletons — safe to share across calls.
_DETERMINISTIC: dict[MutationStrategyName, MutationStrategy] = {
    "lexical": LexicalMutationStrategy(),
    "structural": StructuralMutationStrategy(),
    "multi_turn": MultiTurnMutationStrategy(),
}


def get_strategy(
    name: MutationStrategyName,
    *,
    llm_client: LLMClient | None = None,
    campaign_id: UUID | None = None,
) -> MutationStrategy | AsyncMutationStrategy:
    """Return the strategy instance for `name`.

    Args:
        name: One of 'lexical', 'structural', 'multi_turn', 'llm'.
        llm_client: Required when ``name == 'llm'`` — the shared OpenRouter
            client. Ignored for deterministic strategies.
        campaign_id: Optional, passed through to the LLM strategy for trace
            attribution. Ignored for deterministic strategies.

    Returns:
        Either a sync MutationStrategy (deterministic) or an
        AsyncMutationStrategy (LLM-driven). Callers must dispatch with
        ``isinstance(strategy, AsyncMutationStrategy)``.

    Raises:
        ValueError: If ``name == 'llm'`` but no llm_client was provided.
        KeyError: If `name` is not a registered strategy.
    """
    if name == "llm":
        if llm_client is None:
            raise ValueError(
                "LLMMutationStrategy requires an llm_client; pass one via "
                "get_strategy('llm', llm_client=...)"
            )
        return LLMMutationStrategy(llm_client=llm_client, campaign_id=campaign_id)
    return _DETERMINISTIC[name]
