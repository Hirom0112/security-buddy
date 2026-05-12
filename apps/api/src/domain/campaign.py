"""Domain entities for Campaigns and CampaignBriefs.

Returned by CampaignRepository — ORM models stay inside the repository module.
All entities are frozen (immutable) Pydantic v2 models.

The domain layer imports nothing from agents/, repositories/, routes/,
workers/, or llm_client/ (import-linter contract: domain-leaf).
"""

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CampaignStatus(StrEnum):
    """Allowed campaign lifecycle states (mirrors the DB check constraint)."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    HALTED = "halted"
    BUDGET_WARNING = "budget_warning"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NO_CANDIDATES = "no_candidates"


class BriefStatus(StrEnum):
    """Allowed campaign_brief lifecycle states."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class Campaign(BaseModel):
    """Parsed Campaign entity returned by CampaignRepository."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    status: CampaignStatus
    budget_usd: Decimal
    target_version_id: UUID | None
    target_subcategory: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    version_id: int


class CampaignBrief(BaseModel):
    """Parsed CampaignBrief entity returned by CampaignRepository."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    campaign_id: UUID
    target_subcategory: str
    description: str
    variant_count: int
    success_criteria: dict[str, Any]
    budget_usd: Decimal
    status: BriefStatus
    created_at: datetime
