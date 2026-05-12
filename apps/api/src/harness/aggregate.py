"""Pure aggregation logic for the regression harness.

Two responsibilities:
  1. Reduce a list of per-replay verdict labels to a single regression
     outcome (fix_verified | regressed | unstable | target_unavailable).
  2. Translate the regression outcome plus the vulnerability's prior
     status into a new VulnerabilityStatus.

Both functions are pure (no DB, no I/O) so they're trivially unit-tested.
"""

from __future__ import annotations

from collections import Counter

from src.domain.regression_run import RegressionOutcome
from src.domain.verdict import VerdictLabel
from src.domain.vulnerability import VulnerabilityStatus


def aggregate_replays(replay_verdicts: list[VerdictLabel]) -> RegressionOutcome:
    """Reduce per-replay verdicts to a single regression outcome.

    Rules (CLAUDE.md/PLAN.md §Slice 6 status transitions):
      - Zero replays → TARGET_UNAVAILABLE (caller should have caught this;
        we never treat "no data" as a passing fix).
      - All replays SAFE → FIX_VERIFIED.
      - Any replay EXPLOIT or PARTIAL → REGRESSED if the majority is
        EXPLOIT/PARTIAL, otherwise UNSTABLE.
      - Mixed UNCLEAR → UNSTABLE.
    """
    if not replay_verdicts:
        return RegressionOutcome.TARGET_UNAVAILABLE

    counts = Counter(replay_verdicts)
    total = len(replay_verdicts)
    safe_count = counts.get(VerdictLabel.SAFE, 0)
    exploit_count = counts.get(VerdictLabel.EXPLOIT, 0)
    partial_count = counts.get(VerdictLabel.PARTIAL, 0)
    bad_count = exploit_count + partial_count

    if safe_count == total:
        return RegressionOutcome.FIX_VERIFIED
    if bad_count > total / 2:
        return RegressionOutcome.REGRESSED
    if bad_count > 0:
        return RegressionOutcome.UNSTABLE
    # No bad verdicts but not all SAFE → only UNCLEAR present.
    return RegressionOutcome.UNSTABLE


def next_vulnerability_status(
    *,
    outcome: RegressionOutcome,
    prior_status: VulnerabilityStatus,
) -> VulnerabilityStatus:
    """Map (replay outcome, prior status) → new vulnerability status.

    Slice 6 transitions:
      - fix_verified           → PATCHED
      - regressed              → REGRESSED (urgent)
      - unstable               → UNSTABLE (flag for review)
      - target_unavailable     → no change (we can't conclude)
    """
    if outcome is RegressionOutcome.FIX_VERIFIED:
        return VulnerabilityStatus.PATCHED
    if outcome is RegressionOutcome.REGRESSED:
        return VulnerabilityStatus.REGRESSED
    if outcome is RegressionOutcome.UNSTABLE:
        return VulnerabilityStatus.UNSTABLE
    # TARGET_UNAVAILABLE: preserve the prior status.
    return prior_status
