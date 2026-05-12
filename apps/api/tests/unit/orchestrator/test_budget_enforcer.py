"""Budget enforcer tests — pure function, no I/O."""

from decimal import Decimal

from src.agents.orchestrator.budget_enforcer import (
    BudgetState,
    evaluate,
)


def test_under_warning_threshold_is_ok() -> None:
    decision = evaluate(spent_usd=Decimal("3.99"), budget_usd=Decimal("5.00"))
    assert decision.state is BudgetState.OK
    assert not decision.should_halt
    assert decision.fraction < 0.80


def test_at_warning_threshold_warns() -> None:
    decision = evaluate(spent_usd=Decimal("4.00"), budget_usd=Decimal("5.00"))
    assert decision.state is BudgetState.WARNING
    assert not decision.should_halt


def test_at_exhausted_threshold_halts() -> None:
    decision = evaluate(spent_usd=Decimal("5.00"), budget_usd=Decimal("5.00"))
    assert decision.state is BudgetState.EXHAUSTED
    assert decision.should_halt


def test_overspend_halts() -> None:
    decision = evaluate(spent_usd=Decimal("6.50"), budget_usd=Decimal("5.00"))
    assert decision.state is BudgetState.EXHAUSTED
    assert decision.should_halt
    assert decision.fraction > 1.0


def test_zero_budget_halts() -> None:
    """A misconfigured zero-budget campaign should halt, not divide by zero."""
    decision = evaluate(spent_usd=Decimal("0"), budget_usd=Decimal("0"))
    assert decision.state is BudgetState.EXHAUSTED
    assert decision.should_halt


def test_negative_budget_halts() -> None:
    decision = evaluate(spent_usd=Decimal("0"), budget_usd=Decimal("-1"))
    assert decision.state is BudgetState.EXHAUSTED
    assert decision.should_halt


def test_zero_spent_below_threshold_is_ok() -> None:
    decision = evaluate(spent_usd=Decimal("0"), budget_usd=Decimal("10"))
    assert decision.state is BudgetState.OK
    assert decision.fraction == 0.0
