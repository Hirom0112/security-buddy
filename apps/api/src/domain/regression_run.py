"""Domain entity for a regression run.

Returned by RegressionRunRepository. ORM stays inside the repository.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class RegressionOutcome(StrEnum):
    """Mirrors regression_runs.outcome CHECK constraint."""

    FIX_VERIFIED = "fix_verified"
    REGRESSED = "regressed"
    UNSTABLE = "unstable"
    TARGET_UNAVAILABLE = "target_unavailable"


class RegressionRun(BaseModel):
    """Parsed regression_runs row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    vulnerability_id: UUID
    target_version_id: UUID
    replay_count: int
    verdicts: list[dict[str, Any]]
    outcome: RegressionOutcome
    triggered_by: str
    started_at: datetime
    completed_at: datetime | None
    offending_commit_hash: str | None = None
    kind: str = "exploit_replay"
