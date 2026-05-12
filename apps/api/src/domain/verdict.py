"""Domain entity for Verdicts.

Returned by VerdictRepository. ORM models stay inside the repository module;
this is the parsed, typed representation consumed by agents and routes.

The domain layer imports nothing from agents/, repositories/, routes/,
workers/, or llm_client/ (import-linter contract: domain-leaf).
"""

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class VerdictLabel(StrEnum):
    """Allowed verdict labels — mirrors the verdicts.verdict CHECK constraint."""

    SAFE = "safe"
    EXPLOIT = "exploit"
    PARTIAL = "partial"
    UNCLEAR = "unclear"


class Verdict(BaseModel):
    """Parsed Verdict entity returned by VerdictRepository."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    attack_id: UUID
    verdict: VerdictLabel
    confidence: Decimal
    evidence: str
    notes: str | None
    rubric_version: str
    model_version: str
    created_at: datetime
