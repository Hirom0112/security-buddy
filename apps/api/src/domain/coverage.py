"""Domain types for the Orchestrator's coverage view.

Returned by CoverageRepository. Pure data — no I/O, no SQLAlchemy.

The domain layer imports nothing from agents/, repositories/, routes/,
workers/, or llm_client/ (import-linter contract: domain-leaf).
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class TaxonomyPriority(StrEnum):
    """Mirrors attack_taxonomy.priority CHECK constraint."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CoverageRow(BaseModel):
    """One subcategory's coverage statistics against the current target version.

    All fields are computed from Postgres aggregates by CoverageRepository;
    this struct is what the priority function consumes.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: str
    subcategory: str
    taxonomy_priority: TaxonomyPriority
    attempts: int = Field(ge=0)
    exploit_count: int = Field(ge=0)
    open_findings_count: int = Field(ge=0)
    days_since_last_attempted: int | None = Field(
        default=None,
        description="None when the subcategory has never been attempted.",
    )

    @property
    def success_rate(self) -> float:
        """Exploit verdicts / total attempts. Zero when no attempts."""
        if self.attempts == 0:
            return 0.0
        return self.exploit_count / self.attempts


class PriorityScore(BaseModel):
    """Output of the priority function for a single subcategory."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subcategory: str
    score: float
    breakdown: dict[str, float]
