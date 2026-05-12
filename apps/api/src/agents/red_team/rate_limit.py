"""Outbound rate limiter for the Red Team agent.

Enforces two independent caps (CLAUDE.md §2, PLAN.md Slice 1 #5):

  1. Global throughput: ≤ requests_per_second with a burst allowance.
  2. Per-campaign attack cap: maximum N attacks per campaign_id before
     CampaignAttackCapReached is raised. Bypassable via env var.

Implementation: token-bucket algorithm over an injected clock callable so
tests can fast-forward time without real sleeps.

In-process state only (Slice 1).
# TODO(slice-2): Back this with Redis counters for multi-worker concurrency.
#   The single-worker assumption (one arq worker per campaign) is safe for
#   MVP because arq job pickup uses SKIP LOCKED, so the same brief never
#   runs in two workers simultaneously. If we move to parallel workers per
#   campaign, the per-campaign counter MUST be in Redis.

SECURITY: This limiter is enforced in code, not in prompts. The Orchestrator's
LLM may suggest rates; this module ignores such suggestions and applies the
hard caps regardless (CLAUDE.md §2).
"""

import asyncio
import os
from collections import defaultdict
from collections.abc import Callable
from uuid import UUID

from src.observability.events import log_event

_OVERRIDE_ENV = "SECURITY_BUDDY_RATE_LIMIT_OVERRIDE"
_OVERRIDE_ALLOW = "allow"

_DEFAULT_RPS: float = 10.0
_DEFAULT_BURST: int = 5
_DEFAULT_CAP: int = 1000


class CampaignAttackCapReached(Exception):
    """Raised when a campaign exceeds its attack count ceiling.

    Callers must catch this, mark the campaign 'budget_exhausted' (or a
    suitable terminal state), and stop enqueuing further attack jobs.
    """

    def __init__(self, campaign_id: UUID, cap: int) -> None:
        super().__init__(f"Campaign {campaign_id} has reached the attack cap of {cap}.")
        self.campaign_id = campaign_id
        self.cap = cap


class RateLimiter:
    """Token-bucket outbound rate limiter with per-campaign attack cap.

    The token bucket is global (shared across all campaigns running in this
    process) so that the aggregate outbound rate to the target never exceeds
    requests_per_second * burst regardless of how many campaigns are active.

    Per-campaign counters are tracked independently and reset only via
    reset().

    Args:
        requests_per_second: Sustained throughput ceiling. Default 10.
        burst: Maximum tokens in the bucket (burst allowance). Default 5.
        campaign_attack_cap: Maximum attacks per campaign_id before
            CampaignAttackCapReached. Default 1000.
        clock: Callable returning monotonic time in seconds. Default
            time.monotonic. Injected so tests can fast-forward.
    """

    def __init__(
        self,
        requests_per_second: float = _DEFAULT_RPS,
        burst: int = _DEFAULT_BURST,
        campaign_attack_cap: int = _DEFAULT_CAP,
        clock: Callable[[], float] | None = None,
    ) -> None:
        import time as _time

        self._rps: float = requests_per_second
        self._burst: int = burst
        self._cap: int = campaign_attack_cap
        self._clock: Callable[[], float] = clock if clock is not None else _time.monotonic

        # Token bucket state.
        self._tokens: float = float(burst)
        self._last_refill: float = self._clock()
        self._lock: asyncio.Lock = asyncio.Lock()

        # Per-campaign counters (in-process only — see module TODO above).
        self._campaign_counts: dict[UUID, int] = defaultdict(int)

        # Check override env var once at construction time.
        self._cap_override: bool = (
            os.environ.get(_OVERRIDE_ENV, "").strip().lower() == _OVERRIDE_ALLOW
        )
        if self._cap_override:
            log_event(
                "rate_limit_cap_override_active",
                override_env=_OVERRIDE_ENV,
                override_value=_OVERRIDE_ALLOW,
                warning=(
                    "Per-campaign attack cap is DISABLED via env var. "
                    "Platform may generate more than 1000 attacks per campaign."
                ),
            )

    async def acquire(self, *, campaign_id: UUID) -> None:
        """Block until a token is available, then consume one.

        Also increments the per-campaign counter and raises
        CampaignAttackCapReached on the (N+1)th call for a given campaign_id
        if the override is not active.

        Args:
            campaign_id: The UUID of the active campaign. Used for the
                per-campaign attack counter.

        Raises:
            CampaignAttackCapReached: When the campaign has consumed
                campaign_attack_cap tokens and the override is not active.
        """
        # Check the per-campaign cap BEFORE blocking on the token bucket.
        if not self._cap_override:
            async with self._lock:
                count = self._campaign_counts[campaign_id]
                if count >= self._cap:
                    raise CampaignAttackCapReached(campaign_id, self._cap)

        # Token bucket: block until a token is available.
        await self._consume_token()

        # Increment the per-campaign counter (inside lock for atomicity).
        async with self._lock:
            self._campaign_counts[campaign_id] += 1

    async def _consume_token(self) -> None:
        """Wait until a token is available, then consume one token."""
        while True:
            async with self._lock:
                now = self._clock()
                elapsed = now - self._last_refill
                self._tokens = min(
                    float(self._burst),
                    self._tokens + elapsed * self._rps,
                )
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate how long until the next token arrives.
                wait_needed = (1.0 - self._tokens) / self._rps

            # Release the lock while sleeping so other coroutines can make progress.
            await asyncio.sleep(wait_needed)

    def reset(self, *, campaign_id: UUID) -> None:
        """Reset the per-campaign counter. Intended for use in tests only."""
        self._campaign_counts[campaign_id] = 0

    def get_campaign_count(self, *, campaign_id: UUID) -> int:
        """Return the current attack count for a campaign. Intended for tests."""
        return self._campaign_counts[campaign_id]
