"""Domain entity for Patch — a proposed code fix as a GitHub PR.

Returned by PatchRepository. ORM details live inside the repository.
"""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class PatchStatus(StrEnum):
    """Mirrors patches.status CHECK constraint."""

    AWAITING_HUMAN_REVIEW = "awaiting_human_review"
    MERGED = "merged"
    REJECTED = "rejected"
    CI_FAILED = "ci_failed"
    BLOCKS_LEGIT_FEATURES = "blocks_legit_features"
    # Auto-retry on unstable regression: when attempt #1 lands unstable/
    # regressed and we open attempt #2, the prior patch is flipped to
    # SUPERSEDED so the (vulnerability_id, attempt_number) partial unique
    # index still admits both rows. See migration 0012.
    SUPERSEDED = "superseded"


class Patch(BaseModel):
    """Parsed patches row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    vulnerability_id: UUID
    branch_name: str
    pr_url: str
    status: PatchStatus
    created_at: datetime
    merged_at: datetime | None
    version_id: int
    attempt_number: int = 1
