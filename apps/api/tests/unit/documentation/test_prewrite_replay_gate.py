"""Unit tests for the pre-write replay validation gate aggregation.

Covers _aggregate_replay_gate: the pure quorum logic that decides whether
the Documentation Agent proceeds to mint a vulnerability after the 3-replay
re-fire. ≥2 of 3 exploit/partial → proceed. Anything less → drop.
"""

from __future__ import annotations

from src.domain.verdict import VerdictLabel
from src.workers.documentation_worker import _aggregate_replay_gate


def test_three_of_three_exploit_proceeds() -> None:
    out = _aggregate_replay_gate([VerdictLabel.EXPLOIT, VerdictLabel.EXPLOIT, VerdictLabel.EXPLOIT])
    assert out.proceed is True
    assert out.exploit_replays == 3
    assert out.total_replays == 3


def test_two_of_three_exploit_proceeds() -> None:
    out = _aggregate_replay_gate([VerdictLabel.EXPLOIT, VerdictLabel.EXPLOIT, VerdictLabel.SAFE])
    assert out.proceed is True
    assert out.exploit_replays == 2


def test_partial_counts_toward_quorum() -> None:
    """A 'partial' verdict reproduces enough of the bug to count."""
    out = _aggregate_replay_gate([VerdictLabel.EXPLOIT, VerdictLabel.PARTIAL, VerdictLabel.SAFE])
    assert out.proceed is True
    assert out.exploit_replays == 2


def test_one_of_three_drops() -> None:
    out = _aggregate_replay_gate([VerdictLabel.EXPLOIT, VerdictLabel.SAFE, VerdictLabel.SAFE])
    assert out.proceed is False
    assert out.exploit_replays == 1


def test_zero_of_three_drops() -> None:
    out = _aggregate_replay_gate([VerdictLabel.SAFE, VerdictLabel.SAFE, VerdictLabel.SAFE])
    assert out.proceed is False
    assert out.exploit_replays == 0


def test_unclear_does_not_count() -> None:
    """UNCLEAR (target down, judge couldn't decide) is a non-vote."""
    out = _aggregate_replay_gate([VerdictLabel.EXPLOIT, VerdictLabel.UNCLEAR, VerdictLabel.UNCLEAR])
    assert out.proceed is False
    assert out.exploit_replays == 1
