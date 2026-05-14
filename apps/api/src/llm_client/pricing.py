"""Hardcoded per-model pricing for cost attribution.

OpenRouter returns ``usage.total_cost = 0`` for some models (notably
``anthropic/claude-sonnet-4.6``) even though tokens are billed. The platform
therefore computes cost itself from token counts using the rate table below.

Per CLAUDE.md §6 / §6a discipline, rates live in code — not env, not config,
not a feature flag. Changing a rate is a code commit, surfaced in the PR.

Rates are USD per token (input and output). To convert from the
common "$X / MTok" quote: divide by 1_000_000.
"""

from __future__ import annotations

from decimal import Decimal

from src.observability.events import log_event

# Rates in USD per token. Stored as Decimal strings to avoid binary-float drift
# when multiplied by integer token counts.
_RATES: dict[str, tuple[Decimal, Decimal]] = {
    # Anthropic Claude Sonnet 4.6 — $3.00 / MTok in, $15.00 / MTok out.
    "anthropic/claude-sonnet-4.6": (
        Decimal("0.000003"),
        Decimal("0.000015"),
    ),
    # Meta Llama 3.3 70B Instruct — $0.23 / MTok in, $0.40 / MTok out.
    "meta-llama/llama-3.3-70b-instruct": (
        Decimal("0.00000023"),
        Decimal("0.00000040"),
    ),
}


def compute_cost_usd(model: str, tokens_in: int, tokens_out: int) -> Decimal:
    """Compute USD cost for a completion based on token counts.

    Args:
        model: OpenRouter model identifier.
        tokens_in: Prompt token count.
        tokens_out: Completion token count.

    Returns:
        Decimal cost in USD. Unknown models return ``Decimal("0")`` and emit a
        ``pricing_unknown_model`` event so the gap is visible.
    """
    rates = _RATES.get(model)
    if rates is None:
        log_event(
            "pricing_unknown_model",
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            outcome="failure",
        )
        return Decimal("0")

    rate_in, rate_out = rates
    return rate_in * Decimal(tokens_in) + rate_out * Decimal(tokens_out)
