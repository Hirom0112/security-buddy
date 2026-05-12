"""Strategy registry for Red Team mutation strategies.

Provides a single lookup point: given a MutationStrategyName, return the
corresponding strategy instance. All instances are singletons (stateless
pure-function objects); sharing them across calls is safe.
"""

from src.agents.red_team.mutations.base import MutationStrategy
from src.agents.red_team.mutations.lexical import LexicalMutationStrategy
from src.agents.red_team.mutations.multi_turn import MultiTurnMutationStrategy
from src.agents.red_team.mutations.structural import StructuralMutationStrategy
from src.agents.red_team.types import MutationStrategyName

STRATEGIES: dict[MutationStrategyName, MutationStrategy] = {
    "lexical": LexicalMutationStrategy(),
    "structural": StructuralMutationStrategy(),
    "multi_turn": MultiTurnMutationStrategy(),
}


def get_strategy(name: MutationStrategyName) -> MutationStrategy:
    """Return the strategy instance for `name`.

    Args:
        name: One of 'lexical', 'structural', 'multi_turn'.

    Returns:
        The corresponding MutationStrategy instance.

    Raises:
        KeyError: If `name` is not a registered strategy (should not happen
            if callers use the MutationStrategyName Literal type, but
            defensively raised rather than silently returning None).
    """
    return STRATEGIES[name]
