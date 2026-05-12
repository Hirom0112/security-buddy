"""Deterministic priority math (Layer A of ARCHITECTURE.md §3.1).

Pure function from List[CoverageRow] to ranked List[PriorityScore]. No I/O,
no clock, no random — fully reproducible.

Formula (ARCHITECTURE.md §3.1):

    priority_score =
        taxonomy_priority_weight
      + zero_coverage_bonus  if attempts == 0
      - saturation_penalty   if attempts > 50 and success_rate < 0.02
      + open_findings_weight * open_findings_count
      + staleness_weight     if days_since_last > 7

Weights live in this module as module-level constants; tuning them is a
code commit, not a config change, so the decision rationale is auditable
via git blame.
"""

from typing import Final

from src.domain.coverage import CoverageRow, PriorityScore, TaxonomyPriority

# ---------------------------------------------------------------------------
# Tunable weights — all `Final` so static analysis catches accidental mutation.
# ---------------------------------------------------------------------------

# Base weight assigned by the taxonomy. CRITICAL outweighs HIGH outweighs MED,
# but the differences are intentionally smaller than the dynamic signals
# below so a stale CRITICAL still loses to a fresh open-finding MEDIUM.
_TAXONOMY_WEIGHT: Final[dict[TaxonomyPriority, float]] = {
    TaxonomyPriority.CRITICAL: 10.0,
    TaxonomyPriority.HIGH: 7.0,
    TaxonomyPriority.MEDIUM: 4.0,
    TaxonomyPriority.LOW: 1.0,
}

# Reward for zero-coverage subcategories — strong signal to explore the
# untested surface rather than re-hammering already-covered subcategories.
_ZERO_COVERAGE_BONUS: Final[float] = 5.0

# Penalty for saturation: many attempts, near-zero success. Prevents the
# Orchestrator from looping on subcategories the target has clearly hardened.
_SATURATION_PENALTY: Final[float] = 6.0
_SATURATION_ATTEMPTS_THRESHOLD: Final[int] = 50
_SATURATION_SUCCESS_RATE_CEILING: Final[float] = 0.02

# Each open finding adds to the score so we keep prioritising subcategories
# with unresolved issues until they are patched.
_OPEN_FINDINGS_WEIGHT: Final[float] = 2.0

# Bonus for subcategories not attempted in the last 7 days. Keeps coverage
# fresh against drifting target versions.
_STALENESS_WEIGHT: Final[float] = 3.0
_STALENESS_DAYS_THRESHOLD: Final[int] = 7


def _score_one(row: CoverageRow) -> PriorityScore:
    """Compute the priority score for a single CoverageRow.

    The breakdown dict is included so unit tests and the UI can show why a
    subcategory scored what it did — useful when tuning weights.
    """
    breakdown: dict[str, float] = {}

    taxonomy = _TAXONOMY_WEIGHT[row.taxonomy_priority]
    breakdown["taxonomy"] = taxonomy

    zero_coverage = _ZERO_COVERAGE_BONUS if row.attempts == 0 else 0.0
    breakdown["zero_coverage"] = zero_coverage

    saturation = 0.0
    if (
        row.attempts > _SATURATION_ATTEMPTS_THRESHOLD
        and row.success_rate < _SATURATION_SUCCESS_RATE_CEILING
    ):
        saturation = -_SATURATION_PENALTY
    breakdown["saturation"] = saturation

    open_findings = _OPEN_FINDINGS_WEIGHT * row.open_findings_count
    breakdown["open_findings"] = open_findings

    staleness = 0.0
    if (
        row.days_since_last_attempted is not None
        and row.days_since_last_attempted > _STALENESS_DAYS_THRESHOLD
    ):
        staleness = _STALENESS_WEIGHT
    breakdown["staleness"] = staleness

    score = taxonomy + zero_coverage + saturation + open_findings + staleness
    return PriorityScore(
        subcategory=row.subcategory,
        score=score,
        breakdown=breakdown,
    )


def rank_subcategories(rows: list[CoverageRow]) -> list[PriorityScore]:
    """Return CoverageRows ranked by priority_score, descending.

    Ties broken alphabetically by subcategory so the ranking is stable across
    runs — important for reproducibility in tests and audit logs.
    """
    scored = [_score_one(r) for r in rows]
    scored.sort(key=lambda s: (-s.score, s.subcategory))
    return scored


def pick_top(rows: list[CoverageRow]) -> PriorityScore | None:
    """Return the highest-scoring PriorityScore, or None when input is empty.

    Convenience for the Orchestrator's tick loop, which only needs the top
    candidate.
    """
    ranked = rank_subcategories(rows)
    return ranked[0] if ranked else None
