"""Pure-logic tests for harness.aggregate."""

from __future__ import annotations

from src.domain.regression_run import RegressionOutcome
from src.domain.verdict import VerdictLabel
from src.domain.vulnerability import VulnerabilityStatus
from src.harness.aggregate import aggregate_replays, next_vulnerability_status


def test_empty_replays_is_target_unavailable() -> None:
    assert aggregate_replays([]) is RegressionOutcome.TARGET_UNAVAILABLE


def test_all_safe_is_fix_verified() -> None:
    out = aggregate_replays([VerdictLabel.SAFE] * 3)
    assert out is RegressionOutcome.FIX_VERIFIED


def test_majority_exploit_is_regressed() -> None:
    out = aggregate_replays([VerdictLabel.EXPLOIT, VerdictLabel.EXPLOIT, VerdictLabel.SAFE])
    assert out is RegressionOutcome.REGRESSED


def test_majority_partial_is_regressed() -> None:
    out = aggregate_replays([VerdictLabel.PARTIAL, VerdictLabel.PARTIAL, VerdictLabel.SAFE])
    assert out is RegressionOutcome.REGRESSED


def test_one_exploit_two_safe_is_unstable() -> None:
    out = aggregate_replays([VerdictLabel.EXPLOIT, VerdictLabel.SAFE, VerdictLabel.SAFE])
    assert out is RegressionOutcome.UNSTABLE


def test_all_unclear_is_unstable() -> None:
    out = aggregate_replays([VerdictLabel.UNCLEAR] * 3)
    assert out is RegressionOutcome.UNSTABLE


def test_next_status_fix_verified() -> None:
    out = next_vulnerability_status(
        outcome=RegressionOutcome.FIX_VERIFIED,
        prior_status=VulnerabilityStatus.PROPOSED_FIX,
    )
    assert out is VulnerabilityStatus.PATCHED


def test_next_status_regressed() -> None:
    out = next_vulnerability_status(
        outcome=RegressionOutcome.REGRESSED,
        prior_status=VulnerabilityStatus.PATCHED,
    )
    assert out is VulnerabilityStatus.REGRESSED


def test_next_status_unstable() -> None:
    out = next_vulnerability_status(
        outcome=RegressionOutcome.UNSTABLE,
        prior_status=VulnerabilityStatus.PATCHED,
    )
    assert out is VulnerabilityStatus.UNSTABLE


def test_next_status_target_unavailable_preserves_prior() -> None:
    out = next_vulnerability_status(
        outcome=RegressionOutcome.TARGET_UNAVAILABLE,
        prior_status=VulnerabilityStatus.PATCHED,
    )
    assert out is VulnerabilityStatus.PATCHED
