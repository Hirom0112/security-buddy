"""Unit tests for the model pricing table.

OpenRouter returns total_cost=0 for some models (notably anthropic/claude-sonnet-4.6),
so we compute cost ourselves from token counts using a hardcoded rate table.
Per CLAUDE.md §6/§6a discipline, rates live in code (not env/config).
"""

from __future__ import annotations

from decimal import Decimal

from src.llm_client.pricing import compute_cost_usd


class TestKnownModels:
    def test_sonnet_46_cost_for_nontrivial_tokens(self) -> None:
        # 12,345 input tokens * $3/MTok = 0.037035
        # 6,789  output tokens * $15/MTok = 0.101835
        # total = 0.138870
        result = compute_cost_usd(
            "anthropic/claude-sonnet-4.6",
            tokens_in=12_345,
            tokens_out=6_789,
        )
        assert isinstance(result, Decimal)
        assert result == Decimal("0.138870")

    def test_sonnet_46_zero_tokens(self) -> None:
        result = compute_cost_usd(
            "anthropic/claude-sonnet-4.6",
            tokens_in=0,
            tokens_out=0,
        )
        assert result == Decimal("0")

    def test_llama_33_70b_cost(self) -> None:
        # 1,000,000 input * 0.23e-6 = 0.23
        # 1,000,000 output * 0.40e-6 = 0.40
        # total = 0.63
        result = compute_cost_usd(
            "meta-llama/llama-3.3-70b-instruct",
            tokens_in=1_000_000,
            tokens_out=1_000_000,
        )
        assert result == Decimal("0.63")


class TestUnknownModel:
    def test_unknown_returns_zero(self) -> None:
        result = compute_cost_usd("does-not-exist/mystery-1", 100, 200)
        assert result == Decimal("0")

    def test_unknown_logs_event(self) -> None:
        import logging

        records: list[logging.LogRecord] = []

        class _Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        handler = _Capture(level=logging.DEBUG)
        sb_logger = logging.getLogger("security_buddy")
        sb_logger.addHandler(handler)
        try:
            compute_cost_usd("does-not-exist/mystery-1", 100, 200)
        finally:
            sb_logger.removeHandler(handler)

        # Exactly one structured pricing_unknown_model event should fire.
        matching = [
            r for r in records
            if r.__dict__.get("event") == "pricing_unknown_model"
        ]
        assert len(matching) == 1
        assert matching[0].__dict__.get("model") == "does-not-exist/mystery-1"
        assert matching[0].__dict__.get("outcome") == "failure"


class TestDecimalPrecision:
    def test_no_float_drift(self) -> None:
        # Pick values that would surface binary-float artifacts if floats were used:
        # 1 input token * 3e-6 = 0.000003 exactly; in float64 this is 2.9999...e-6
        result = compute_cost_usd(
            "anthropic/claude-sonnet-4.6",
            tokens_in=1,
            tokens_out=0,
        )
        assert isinstance(result, Decimal)
        # exact decimal, not a float-derived string like '2.9999999999999997e-06'
        assert result == Decimal("0.000003")
        assert str(result) == "0.000003"

    def test_sum_is_exact(self) -> None:
        # 3 input tokens + 7 output tokens at Sonnet rates
        # = 3 * 3e-6 + 7 * 15e-6 = 9e-6 + 105e-6 = 114e-6 = 0.000114
        result = compute_cost_usd(
            "anthropic/claude-sonnet-4.6",
            tokens_in=3,
            tokens_out=7,
        )
        assert result == Decimal("0.000114")
