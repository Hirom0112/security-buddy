"""Priority math tests — every signal in the formula gets a dedicated case.

ARCHITECTURE.md §3.1:
  priority_score =
      taxonomy_priority_weight
    + zero_coverage_bonus     if attempts == 0
    - saturation_penalty      if attempts > 50 and success_rate < 0.02
    + open_findings_weight * open_findings_count
    + staleness_weight        if days_since_last > 7
"""

from src.agents.orchestrator.priority import (
    pick_top,
    rank_subcategories,
)
from src.domain.coverage import CoverageRow, TaxonomyPriority


def _row(
    *,
    subcategory: str = "prompt_injection/direct",
    taxonomy: TaxonomyPriority = TaxonomyPriority.HIGH,
    attempts: int = 10,
    exploits: int = 0,
    open_findings: int = 0,
    days_since: int | None = 1,
    category: str = "prompt_injection",
) -> CoverageRow:
    return CoverageRow(
        category=category,
        subcategory=subcategory,
        taxonomy_priority=taxonomy,
        attempts=attempts,
        exploit_count=exploits,
        open_findings_count=open_findings,
        days_since_last_attempted=days_since,
    )


# ---------------------------------------------------------------------------
# Per-signal coverage
# ---------------------------------------------------------------------------


def test_taxonomy_critical_outweighs_low() -> None:
    crit = _row(subcategory="a", taxonomy=TaxonomyPriority.CRITICAL)
    low = _row(subcategory="b", taxonomy=TaxonomyPriority.LOW)
    top = pick_top([crit, low])
    assert top is not None
    assert top.subcategory == "a"


def test_zero_coverage_bonus_applied_when_no_attempts() -> None:
    zero = _row(subcategory="a", attempts=0, days_since=None)
    covered = _row(subcategory="b", attempts=10)
    top = pick_top([zero, covered])
    assert top is not None
    assert top.subcategory == "a"
    assert top.breakdown["zero_coverage"] > 0


def test_zero_coverage_bonus_not_applied_when_attempts_exist() -> None:
    row = _row(attempts=1)
    scored = rank_subcategories([row])[0]
    assert scored.breakdown["zero_coverage"] == 0


def test_saturation_penalty_applied_when_many_attempts_and_low_success() -> None:
    saturated = _row(subcategory="a", attempts=100, exploits=1)  # 1% success
    fresh = _row(subcategory="b", attempts=5, exploits=0, days_since=1)
    top = pick_top([saturated, fresh])
    assert top is not None
    assert top.subcategory == "b"
    sat_score = next(s for s in rank_subcategories([saturated, fresh]) if s.subcategory == "a")
    assert sat_score.breakdown["saturation"] < 0


def test_saturation_penalty_not_applied_below_attempts_threshold() -> None:
    row = _row(attempts=50, exploits=0)  # at threshold, not above
    scored = rank_subcategories([row])[0]
    assert scored.breakdown["saturation"] == 0


def test_saturation_penalty_not_applied_when_success_rate_high() -> None:
    # Many attempts but exploitable surface — keep prioritising.
    row = _row(attempts=200, exploits=20)  # 10% success
    scored = rank_subcategories([row])[0]
    assert scored.breakdown["saturation"] == 0


def test_open_findings_boost_scales_with_count() -> None:
    one = _row(subcategory="a", open_findings=1)
    five = _row(subcategory="b", open_findings=5)
    ranked = rank_subcategories([one, five])
    assert ranked[0].subcategory == "b"
    diff = ranked[0].breakdown["open_findings"] - ranked[1].breakdown["open_findings"]
    assert diff > 0


def test_staleness_bonus_applied_when_days_above_7() -> None:
    stale = _row(subcategory="a", days_since=10)
    fresh = _row(subcategory="b", days_since=3)
    top = pick_top([stale, fresh])
    assert top is not None
    assert top.subcategory == "a"
    assert top.breakdown["staleness"] > 0


def test_staleness_bonus_not_applied_when_days_at_threshold() -> None:
    row = _row(days_since=7)
    assert rank_subcategories([row])[0].breakdown["staleness"] == 0


def test_staleness_not_applied_when_never_attempted() -> None:
    """days_since_last_attempted=None must NOT trigger staleness.

    Zero-coverage handles the never-attempted case separately so we don't
    double-count.
    """
    row = _row(attempts=0, days_since=None)
    scored = rank_subcategories([row])[0]
    assert scored.breakdown["staleness"] == 0
    assert scored.breakdown["zero_coverage"] > 0


# ---------------------------------------------------------------------------
# Composition + edge cases
# ---------------------------------------------------------------------------


def test_open_finding_low_priority_can_outrank_stale_critical() -> None:
    """A subcategory with open findings is more important than tax priority alone."""
    # CRITICAL stale: 10 + 3 = 13
    crit = _row(subcategory="a", taxonomy=TaxonomyPriority.CRITICAL, days_since=14)
    # LOW with 7 open findings: 1 + 2*7 = 15
    low = _row(subcategory="b", taxonomy=TaxonomyPriority.LOW, open_findings=7)
    top = pick_top([crit, low])
    assert top is not None
    assert top.subcategory == "b"


def test_ranking_is_stable_and_alphabetical_on_ties() -> None:
    a = _row(subcategory="bravo", taxonomy=TaxonomyPriority.HIGH, days_since=1)
    b = _row(subcategory="alpha", taxonomy=TaxonomyPriority.HIGH, days_since=1)
    ranked = rank_subcategories([a, b])
    assert [s.subcategory for s in ranked] == ["alpha", "bravo"]


def test_pick_top_returns_none_on_empty_input() -> None:
    assert pick_top([]) is None


def test_breakdown_keys_are_stable() -> None:
    scored = rank_subcategories([_row()])[0]
    assert set(scored.breakdown) == {
        "taxonomy",
        "zero_coverage",
        "saturation",
        "open_findings",
        "staleness",
    }


def test_score_equals_sum_of_breakdown() -> None:
    row = _row(
        taxonomy=TaxonomyPriority.HIGH,
        attempts=0,
        open_findings=2,
        days_since=None,
    )
    scored = rank_subcategories([row])[0]
    assert scored.score == sum(scored.breakdown.values())


def test_priority_score_is_frozen() -> None:
    """Returned PriorityScore values are immutable — protects audit logs."""
    import pytest

    scored = rank_subcategories([_row()])[0]
    with pytest.raises(Exception):  # noqa: B017 — pydantic raises on frozen mutation
        scored.score = 0.0  # type: ignore[misc]
