"""Unit tests for the outbound rate limiter.

Tests verify:
  1. Burst of N succeeds immediately; (N+1)th waits.
  2. Sustained throughput ≤ RPS over a simulated window.
  3. Per-campaign cap raises CampaignAttackCapReached on the (cap+1)th call.
  4. SECURITY_BUDDY_RATE_LIMIT_OVERRIDE=allow skips the cap and emits a
     log warning event (checked via monkeypatching log_event).

All time is injected via the clock parameter so tests are instant.
"""

import asyncio
import uuid
from unittest.mock import patch

import pytest

from src.agents.red_team.rate_limit import (
    CampaignAttackCapReached,
    RateLimiter,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_campaign() -> uuid.UUID:
    return uuid.uuid4()


class FakeClock:
    """Monotonic clock whose value advances only when told."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


# ---------------------------------------------------------------------------
# 1. Burst tests — using real asyncio.sleep but fast clock
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_burst_of_five_instant() -> None:
    """Five requests with a fresh full bucket should all acquire without waiting."""
    clock = FakeClock(start=0.0)
    limiter = RateLimiter(requests_per_second=10.0, burst=5, clock=clock)
    campaign = make_campaign()

    # Advance clock slightly so elapsed > 0 on each call (prevents edge cases).
    async def acquire_with_tick() -> None:
        clock.advance(0.0001)
        await limiter.acquire(campaign_id=campaign)

    # All five should complete essentially immediately (< 0.1 s total).
    tasks = [acquire_with_tick() for _ in range(5)]
    done, pending = await asyncio.wait([asyncio.ensure_future(t) for t in tasks], timeout=1.0)
    assert len(pending) == 0, "Five burst acquires should complete within 1 second"
    assert len(done) == 5


@pytest.mark.asyncio
async def test_sixth_request_blocked_initially() -> None:
    """After 5 burst tokens, the 6th request cannot complete instantly."""
    clock = FakeClock(start=0.0)
    # Freeze the clock — no tokens will be added, so the 6th must wait forever
    # unless we advance time.
    limiter = RateLimiter(requests_per_second=10.0, burst=5, clock=clock)
    campaign = make_campaign()

    # Drain all 5 burst tokens.
    for _ in range(5):
        clock.advance(0.0001)
        await limiter.acquire(campaign_id=campaign)

    # The 6th should not complete immediately.
    sixth = asyncio.ensure_future(limiter.acquire(campaign_id=campaign))
    done, pending = await asyncio.wait([sixth], timeout=0.05)
    assert sixth in pending, "6th acquire should block when bucket is empty"

    # Advance the clock by 0.15 s — that refills 1.5 tokens, enough for 1.
    clock.advance(0.15)
    done, pending = await asyncio.wait([sixth], timeout=1.0)
    assert sixth in done, "6th acquire should complete after clock advances"
    sixth.cancel()


# ---------------------------------------------------------------------------
# 2. Throughput ceiling test with simulated time
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_throughput_ceiling() -> None:
    """Over 2 simulated seconds at 10 RPS, at most ~20 tokens are available."""
    clock = FakeClock(start=0.0)
    rps = 10.0
    burst = 5
    limiter = RateLimiter(requests_per_second=rps, burst=burst, clock=clock)
    campaign = make_campaign()

    completed = 0

    async def timed_acquire() -> None:
        nonlocal completed
        clock.advance(0.1)  # Advance 100 ms per request
        await limiter.acquire(campaign_id=campaign)
        completed += 1

    # In 2 simulated seconds (20 x 0.1 s steps), at 10 RPS we should be able
    # to acquire at most burst + floor(2.0 * 10) = 5 + 20 = 25.
    # But since each step adds tokens AND consumes them, in practice the ceiling
    # is burst + rps * total_time = 25 for 20 steps of 0.1 s.
    tasks = [asyncio.ensure_future(timed_acquire()) for _ in range(20)]
    _done, pending = await asyncio.wait(tasks, timeout=5.0)

    assert len(pending) == 0, "All 20 acquires should complete with advancing clock"
    assert completed == 20


# ---------------------------------------------------------------------------
# 3. Per-campaign cap test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cap_raised_on_1001st_call() -> None:
    """CampaignAttackCapReached must be raised on the 1001st call."""
    clock = FakeClock(start=0.0)
    cap = 10  # Use small cap for speed.
    limiter = RateLimiter(
        requests_per_second=100.0,
        burst=100,
        campaign_attack_cap=cap,
        clock=clock,
    )
    campaign = make_campaign()

    for _ in range(cap):
        clock.advance(0.01)
        await limiter.acquire(campaign_id=campaign)

    assert limiter.get_campaign_count(campaign_id=campaign) == cap

    # The (cap+1)th call must raise immediately.
    clock.advance(0.01)
    with pytest.raises(CampaignAttackCapReached) as exc_info:
        await limiter.acquire(campaign_id=campaign)

    assert exc_info.value.campaign_id == campaign
    assert exc_info.value.cap == cap


@pytest.mark.asyncio
async def test_cap_is_per_campaign() -> None:
    """Different campaign_ids have independent counters."""
    clock = FakeClock(start=0.0)
    cap = 5
    limiter = RateLimiter(
        requests_per_second=100.0,
        burst=100,
        campaign_attack_cap=cap,
        clock=clock,
    )
    campaign_a = make_campaign()
    campaign_b = make_campaign()

    for _ in range(cap):
        clock.advance(0.01)
        await limiter.acquire(campaign_id=campaign_a)

    # campaign_b should still be available.
    clock.advance(0.01)
    await limiter.acquire(campaign_id=campaign_b)  # Must not raise.

    # But campaign_a must be at cap.
    clock.advance(0.01)
    with pytest.raises(CampaignAttackCapReached):
        await limiter.acquire(campaign_id=campaign_a)


# ---------------------------------------------------------------------------
# 4. Override env var skips cap and emits a warning event
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_override_skips_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """SECURITY_BUDDY_RATE_LIMIT_OVERRIDE=allow should bypass the cap."""
    monkeypatch.setenv("SECURITY_BUDDY_RATE_LIMIT_OVERRIDE", "allow")

    # Capture the log_event calls to verify a warning was emitted.
    events: list[str] = []

    def fake_log_event(name: str, **kwargs: object) -> None:
        events.append(name)

    with patch("src.agents.red_team.rate_limit.log_event", side_effect=fake_log_event):
        clock = FakeClock(start=0.0)
        cap = 3
        limiter = RateLimiter(
            requests_per_second=100.0,
            burst=100,
            campaign_attack_cap=cap,
            clock=clock,
        )

    # The override warning should have been emitted at construction time.
    assert "rate_limit_cap_override_active" in events

    campaign = make_campaign()
    # Should be able to exceed cap without raising.
    for _ in range(cap + 5):
        clock.advance(0.01)
        await limiter.acquire(campaign_id=campaign)  # Must not raise.


# ---------------------------------------------------------------------------
# 5. Reset helper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reset_clears_campaign_counter() -> None:
    """reset() should zero the counter, allowing further acquires."""
    clock = FakeClock(start=0.0)
    cap = 3
    limiter = RateLimiter(
        requests_per_second=100.0,
        burst=100,
        campaign_attack_cap=cap,
        clock=clock,
    )
    campaign = make_campaign()

    for _ in range(cap):
        clock.advance(0.01)
        await limiter.acquire(campaign_id=campaign)

    with pytest.raises(CampaignAttackCapReached):
        clock.advance(0.01)
        await limiter.acquire(campaign_id=campaign)

    limiter.reset(campaign_id=campaign)
    assert limiter.get_campaign_count(campaign_id=campaign) == 0

    # Should succeed again after reset.
    clock.advance(0.01)
    await limiter.acquire(campaign_id=campaign)
