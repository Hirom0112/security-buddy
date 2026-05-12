"""Pydantic schemas for the brief generator's structured LLM output."""

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field


class GeneratedBrief(BaseModel):
    """Parsed LLM response framing a campaign brief.

    The LLM does not pick the subcategory — that comes from the priority
    function. The LLM only fills in description + variant_count + budget
    proposal + success criteria. variant_count and budget are validated and
    capped by the worker before persistence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: str = Field(..., min_length=20, max_length=4000)
    proposed_variant_count: int = Field(..., ge=1, le=200)
    proposed_budget_usd: Decimal = Field(..., gt=Decimal("0"), le=Decimal("100"))
    success_criteria: dict[str, str | bool | int | float] = Field(default_factory=dict)
    rationale: str = Field(..., min_length=10, max_length=2000)
