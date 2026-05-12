"""Domain entity for TargetVersion.

Returned by TargetVersionRepository. ORM stays inside the repository.
"""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class TargetVersion(BaseModel):
    """Parsed target_versions row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    target_manifest_id: UUID
    target_id: str
    version: str
    deployed_at: datetime
    triggered_by: str | None
