"""Brief generator tests — exercise the parse path and fallback contract.

The LLM call itself is mocked; we only test the deterministic glue.
"""

from decimal import Decimal
from unittest.mock import AsyncMock

import pytest

from src.agents.orchestrator.brief_generator import _fallback_brief, _parse, generate_brief
from src.agents.orchestrator.schema import GeneratedBrief
from src.domain.coverage import CoverageRow, PriorityScore, TaxonomyPriority
from src.llm_client.types import Completion, TokenUsage


def _priority() -> PriorityScore:
    return PriorityScore(
        subcategory="prompt_injection/indirect_via_upload",
        score=15.0,
        breakdown={
            "taxonomy": 10.0,
            "zero_coverage": 0.0,
            "saturation": 0.0,
            "open_findings": 2.0,
            "staleness": 3.0,
        },
    )


def _row() -> CoverageRow:
    return CoverageRow(
        category="prompt_injection",
        subcategory="prompt_injection/indirect_via_upload",
        taxonomy_priority=TaxonomyPriority.CRITICAL,
        attempts=12,
        exploit_count=1,
        open_findings_count=1,
        days_since_last_attempted=14,
    )


_VALID_LLM = """{
    "description": "Run indirect prompt-injection variants against the document upload surface to probe identity persistence and the canary boundary.",
    "proposed_variant_count": 12,
    "proposed_budget_usd": 2.50,
    "success_criteria": {"canary_absent": true, "identity_persists": true},
    "rationale": "Open finding plus 14 days of staleness keeps this subcategory at the top of the queue."
}"""


def test_parse_valid_object() -> None:
    brief = _parse(_VALID_LLM)
    assert brief.proposed_variant_count == 12
    assert brief.proposed_budget_usd == Decimal("2.50")


def test_parse_fenced_object() -> None:
    fenced = f"```json\n{_VALID_LLM}\n```"
    brief = _parse(fenced)
    assert brief.proposed_variant_count == 12


def test_parse_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        _parse("")


def test_parse_rejects_extra_fields() -> None:
    bad = '{"description": "x" * 30, "proposed_variant_count": 1, "proposed_budget_usd": 1.0, "success_criteria": {}, "rationale": "abcdefghij", "extra": "no"}'
    with pytest.raises(ValueError):
        _parse(bad)


def test_parse_rejects_out_of_range_variant_count() -> None:
    bad = '{"description": "x".rjust(30), "proposed_variant_count": 500, "proposed_budget_usd": 1.0, "success_criteria": {}, "rationale": "abcdefghij"}'
    with pytest.raises(ValueError):
        _parse(bad)


def test_fallback_brief_is_well_formed() -> None:
    brief = _fallback_brief(_priority(), _row())
    assert isinstance(brief, GeneratedBrief)
    assert brief.proposed_variant_count == 10
    assert brief.proposed_budget_usd == Decimal("5.00")
    assert "Deterministic fallback" in brief.rationale


@pytest.mark.asyncio
async def test_generate_brief_returns_parsed_when_llm_succeeds() -> None:
    completion = Completion(
        model="anthropic/claude-sonnet-4.6",
        content=_VALID_LLM,
        usage=TokenUsage(prompt_tokens=100, completion_tokens=80, total_tokens=180),
        cost_usd=0.0012,
        duration_ms=300.0,
        prompt_hash="a" * 64,
        completion_hash="b" * 64,
    )
    client = AsyncMock()
    client.complete.return_value = completion

    brief, used_fallback = await generate_brief(
        priority=_priority(),
        row=_row(),
        manifest_fragment={},
        llm_client=client,
    )

    assert not used_fallback
    assert brief.proposed_variant_count == 12


@pytest.mark.asyncio
async def test_generate_brief_falls_back_on_parse_failure() -> None:
    completion = Completion(
        model="anthropic/claude-sonnet-4.6",
        content="I refuse to do that.",
        usage=TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        cost_usd=0.0001,
        duration_ms=200.0,
        prompt_hash="a" * 64,
        completion_hash="b" * 64,
    )
    client = AsyncMock()
    client.complete.return_value = completion

    brief, used_fallback = await generate_brief(
        priority=_priority(),
        row=_row(),
        manifest_fragment={},
        llm_client=client,
    )

    assert used_fallback
    assert "Deterministic fallback" in brief.rationale


@pytest.mark.asyncio
async def test_generate_brief_falls_back_on_exception() -> None:
    client = AsyncMock()
    client.complete.side_effect = RuntimeError("network blew up")

    brief, used_fallback = await generate_brief(
        priority=_priority(),
        row=_row(),
        manifest_fragment={},
        llm_client=client,
    )

    assert used_fallback
    assert brief.proposed_variant_count == 10
