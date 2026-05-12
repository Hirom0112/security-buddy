"""Domain types for the Red Team agent.

These types are the contract between the seed library, mutation strategies,
and the target client. Consumed by the Judge (via Postgres rows) and the
Orchestrator (via coverage queries), but never imported from those agents.

All models are frozen (immutable) to prevent accidental mutation of
attack payloads after construction — per CLAUDE.md §4, payloads are
data, not instructions.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SeedAttack(BaseModel):
    """A seed attack loaded from seeds/<subcategory>.json.

    The base unit a mutation strategy consumes. Seeds are authored once and
    are not generated at runtime — they encode known adversarial patterns
    for a specific subcategory.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed_id: str
    """Stable identifier, e.g. 'seed-pii-cross-patient-001'."""

    category: str
    """Top-level category, e.g. 'data_exfiltration'."""

    subcategory: str
    """Dotted path, e.g. 'data_exfiltration/cross_patient_leakage'."""

    message_template: str
    """The base adversarial input as a string. May contain {placeholder}
    tokens that mutation strategies fill in deterministically."""

    target_endpoint: str
    """Target endpoint the attack is fired at, e.g. 'POST /agent/query'."""

    framework_mappings: dict[str, str | list[str]]
    """OWASP / MITRE ATLAS / HIPAA IDs for this seed's subcategory.
    Example: {'owasp_llm': 'LLM01:2025', 'mitre_atlas': 'AML.T0051.001',
               'hipaa': ['164.312(a)(1)', '164.312(c)(1)']}
    """

    expected_safe_behavior: str
    """Plain prose fed to the Judge as a rubric hint. Describes what a
    correctly-functioning Co-Pilot should do when receiving this attack."""

    judge_rubric_hints: dict[str, str]
    """Structured hints for the Judge. Keys: 'success_criteria',
    'trust_boundaries_at_stake', 'evidence_required'."""

    tags: list[str] = Field(default_factory=list)
    """Free-form tags for coverage queries, e.g. ['cross-patient', 'rag']."""


MutationStrategyName = Literal["lexical", "structural", "multi_turn"]


class Variant(BaseModel):
    """The output of a mutation strategy: an attack ready to fire.

    For single-turn attacks, attack_input is a str.
    For multi-turn sequences, attack_input is a list[str] where each element
    is one turn sent in order.

    Variants are immutable. Once constructed they are written to Postgres
    as-is — no further modification.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed_id: str
    """ID of the SeedAttack this variant was derived from."""

    variant_index: int
    """Zero-based index within the batch produced by one mutate() call."""

    mutation_strategy: MutationStrategyName

    category: str
    """Copied from the source SeedAttack."""

    subcategory: str
    """Copied from the source SeedAttack. Never altered by mutation."""

    attack_input: str | list[str]
    """The actual text to send to the target. str for single-turn,
    list[str] for multi-turn (ordered turns)."""

    attack_metadata: dict[str, str | int | bool]
    """Transform notes for observability and coverage queries.
    Must include 'transform' key. May include 'knob', 'variant_label', etc.
    Example: {'transform': 'synonym_swap', 'knob': 'v2'}
    """

    judge_rubric_hints: dict[str, str]
    """Passed through from the source SeedAttack unchanged so the Judge
    has the rubric context even when looking only at the Variant row."""

    target_endpoint: str
    """Copied from the source SeedAttack."""
