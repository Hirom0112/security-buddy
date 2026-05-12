"""Domain entity for TargetManifest.

Returned by TargetManifestRepository — the ORM model stays inside the
repository module; this is the parsed, typed representation used by
the rest of the system.

The domain layer imports nothing from agents/, repositories/, routes/,
workers/, or llm_client/ (import-linter contract: domain-leaf).
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class TargetManifest(BaseModel):
    """Parsed TargetManifest entity returned by TargetManifestRepository."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    target_id: str
    manifest_json: dict[str, Any]
    version: str
    created_at: datetime
