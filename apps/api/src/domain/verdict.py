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
    # Terminal state set by the Documentation Agent when a pre-write 3-replay
    # validation fails to reproduce the exploit. The verdict will not be
    # reconsidered on retry. See workers/documentation_worker.py and migration
    # 0013.
    REPLAY_UNSTABLE = "replay_unstable"


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
    data_actually_disclosed: bool | None = None
    """True iff the Judge concluded the target response leaked content the
    attacker would not otherwise have had. False when an unauthorized
    action executed but the response carried no exfiltrated content
    (empty list, error envelope, refusal). None for legacy rows judged
    before this field existed."""
