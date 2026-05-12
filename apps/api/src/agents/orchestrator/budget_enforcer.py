"""Budget enforcer — pure Python on top of agent_traces aggregate.

ARCHITECTURE.md §3.1 cost discipline:
  - >=80% of budget → mark campaign budget_warning, keep running
  - >=100% of budget → mark budget_exhausted, halt

The enforcer is a single function so the orchestrator tick + future per-attack
callback both call the same code.
"""

from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class BudgetState(StrEnum):
    """Outcome of a budget check."""

    OK = "ok"
    WARNING = "warning"
    EXHAUSTED = "exhausted"


class BudgetDecision(BaseModel):
    """Pure data — what the caller should do given the budget state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: BudgetState
    spent_usd: Decimal
    budget_usd: Decimal
    fraction: float  # spent / budget, capped at 0 if budget is zero
    should_halt: bool


_WARNING_THRESHOLD: float = 0.80
_EXHAUSTED_THRESHOLD: float = 1.00


def evaluate(
    *,
    spent_usd: Decimal,
    budget_usd: Decimal,
) -> BudgetDecision:
    """Decide whether the campaign should halt, warn, or continue.

    Both values are Decimal to match the schema column type and avoid
    binary-float drift on accumulating sums of fractional cents.
    """
    if budget_usd <= Decimal("0"):
        # Zero or negative budget is a configuration bug; treat as exhausted.
        return BudgetDecision(
            state=BudgetState.EXHAUSTED,
            spent_usd=spent_usd,
            budget_usd=budget_usd,
            fraction=0.0,
            should_halt=True,
        )

    fraction = float(spent_usd / budget_usd)

    if fraction >= _EXHAUSTED_THRESHOLD:
        state = BudgetState.EXHAUSTED
        should_halt = True
    elif fraction >= _WARNING_THRESHOLD:
        state = BudgetState.WARNING
        should_halt = False
    else:
        state = BudgetState.OK
        should_halt = False

    return BudgetDecision(
        state=state,
        spent_usd=spent_usd,
        budget_usd=budget_usd,
        fraction=fraction,
        should_halt=should_halt,
    )
