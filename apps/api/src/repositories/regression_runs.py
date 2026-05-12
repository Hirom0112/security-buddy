"""RegressionRunRepository — write side for the harness.

Architectural boundary (import-linter): imports from src.domain only.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import sqlalchemy as sa

from src.domain.regression_run import RegressionOutcome, RegressionRun

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

_COLS = (
    "id, vulnerability_id, target_version_id, replay_count, verdicts,"
    " outcome, triggered_by, started_at, completed_at"
)


class RegressionRunRepository:
    """Read and write rows in the regression_runs table."""

    async def list_for_vulnerability(
        self, session: AsyncSession, vulnerability_id: UUID, *, limit: int = 20
    ) -> list[RegressionRun]:
        result = await session.execute(
            sa.text(
                f"SELECT {_COLS} FROM regression_runs"  # noqa: S608
                " WHERE vulnerability_id = :vid"
                " ORDER BY started_at DESC LIMIT :lim"
            ),
            {"vid": str(vulnerability_id), "lim": limit},
        )
        rows = result.mappings().all()
        return [RegressionRun.model_validate(dict(r)) for r in rows]

    async def create(
        self,
        session: AsyncSession,
        *,
        vulnerability_id: UUID,
        target_version_id: UUID,
        replay_count: int,
        verdicts: list[dict[str, Any]],
        outcome: RegressionOutcome,
        triggered_by: str,
    ) -> RegressionRun:
        result = await session.execute(
            sa.text(
                "INSERT INTO regression_runs"  # noqa: S608
                " (vulnerability_id, target_version_id, replay_count,"
                "  verdicts, outcome, triggered_by, completed_at)"
                " VALUES (:vid, :tvid, :n, CAST(:v AS jsonb), :o, :tb, now())"
                f" RETURNING {_COLS}"
            ),
            {
                "vid": str(vulnerability_id),
                "tvid": str(target_version_id),
                "n": replay_count,
                "v": json.dumps(verdicts),
                "o": outcome.value,
                "tb": triggered_by,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("regression_runs INSERT returned no row")
        return RegressionRun.model_validate(dict(row))
