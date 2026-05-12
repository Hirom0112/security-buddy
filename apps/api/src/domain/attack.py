"""Domain entity for Attacks.

Returned by AttackRepository — the ORM model stays inside the repository
module; this is the parsed, typed representation used by the rest of the system.

The domain layer imports nothing from agents/, repositories/, routes/,
workers/, or llm_client/ (import-linter contract: domain-leaf).
"""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AttackStatus(StrEnum):
    """Allowed attack lifecycle states (mirrors the DB check constraint)."""

    PENDING_EXECUTION = "pending_execution"
    AWAITING_JUDGMENT = "awaiting_judgment"
    JUDGED = "judged"
    TARGET_UNAVAILABLE = "target_unavailable"


class Attack(BaseModel):
    """Parsed Attack entity returned by AttackRepository."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    campaign_id: UUID
    brief_id: UUID
    category: str
    subcategory: str
    mutation_strategy: str
    seed_used: str | None
    attack_input: str
    attack_metadata: dict[str, Any]
    target_response: str | None
    target_response_status: int | None
    target_response_time_ms: int | None
    status: AttackStatus
    created_at: datetime
    executed_at: datetime | None
