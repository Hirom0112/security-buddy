"""Pydantic schemas for the Documentation Agent.

VulnerabilityDraft is the parsed LLM output BEFORE the worker enforces the
deterministic checks (framework citation match, severity floor, PHI scrub).
The worker then composes the final vulnerabilities row.
"""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Mirrors the vulnerabilities.severity CHECK constraint."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Numeric rank, higher = more severe. Useful for `max()`."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


class VulnerabilityDraft(BaseModel):
    """Parsed LLM response containing the report content fields.

    The framework IDs are NOT in this schema — they come from
    attack_taxonomy.framework_mappings via framework_lookup.py. The LLM
    must not be allowed to invent framework citations.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: str = Field(..., min_length=10, max_length=300)
    severity: Severity
    clinical_impact: str = Field(..., min_length=20, max_length=4000)
    reproduction_steps: str = Field(..., min_length=20, max_length=8000)
    observed_behavior: str = Field(..., min_length=10, max_length=4000)
    expected_behavior: str = Field(..., min_length=10, max_length=4000)
    recommended_remediation: str = Field(..., min_length=20, max_length=4000)


class FrameworkCitation(BaseModel):
    """Resolved framework citation for a single subcategory.

    Sourced from attack_taxonomy.framework_mappings + framework_versions —
    never from the LLM. CLAUDE.md §6a.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    owasp_llm_id: str
    mitre_atlas_technique_id: str
    hipaa_safeguard: str  # joined when the taxonomy lists multiple
    framework_versions: dict[str, str]
