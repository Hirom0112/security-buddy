"""TargetVersionRepository — reads only, for the harness.

A target_versions row records one observed deployment of a target. The
harness uses the most-recently-deployed row as the version to attribute
replay results to.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa

from src.domain.target_version import TargetVersion

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


class TargetVersionRepository:
    async def get_latest(
        self, session: AsyncSession, *, target_id: str | None = None
    ) -> TargetVersion | None:
        if target_id is None:
            result = await session.execute(
                sa.text(
                    "SELECT id, target_manifest_id, target_id, version,"
                    " deployed_at, triggered_by FROM target_versions"
                    " ORDER BY deployed_at DESC LIMIT 1"
                )
            )
        else:
            result = await session.execute(
                sa.text(
                    "SELECT id, target_manifest_id, target_id, version,"
                    " deployed_at, triggered_by FROM target_versions"
                    " WHERE target_id = :tid"
                    " ORDER BY deployed_at DESC LIMIT 1"
                ),
                {"tid": target_id},
            )
        row = result.mappings().first()
        return TargetVersion.model_validate(dict(row)) if row else None

    async def get_or_create_latest(
        self,
        session: AsyncSession,
        *,
        target_manifest_id: UUID,
        target_id: str,
        version: str,
        triggered_by: str | None,
    ) -> TargetVersion:
        """Return the latest target_versions row, creating one if none exist.

        Used by the regression worker when the GitHub merge webhook fires
        but no target_version row has been recorded yet. version is a free-
        form string (commit SHA, semver tag, etc.).
        """
        existing = await self.get_latest(session, target_id=target_id)
        if existing is not None and existing.version == version:
            return existing
        result = await session.execute(
            sa.text(
                "INSERT INTO target_versions"
                " (target_manifest_id, target_id, version, deployed_at,"
                "  triggered_by)"
                " VALUES (:tmid, :tid, :ver, now(), :tb)"
                " ON CONFLICT (target_id, version) DO UPDATE"
                "   SET deployed_at = EXCLUDED.deployed_at"
                " RETURNING id, target_manifest_id, target_id, version,"
                "  deployed_at, triggered_by"
            ),
            {
                "tmid": str(target_manifest_id),
                "tid": target_id,
                "ver": version,
                "tb": triggered_by,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("target_versions upsert returned no row")
        return TargetVersion.model_validate(dict(row))
