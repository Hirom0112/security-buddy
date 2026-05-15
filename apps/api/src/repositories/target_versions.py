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


_COLS = "id, target_manifest_id, target_id, version, commit_hash, deployed_at, triggered_by"


class TargetVersionRepository:
    async def get_by_id(self, session: AsyncSession, version_id: UUID) -> TargetVersion | None:
        result = await session.execute(
            sa.text(
                f"SELECT {_COLS} FROM target_versions WHERE id = :id"  # noqa: S608
            ),
            {"id": str(version_id)},
        )
        row = result.mappings().first()
        return TargetVersion.model_validate(dict(row)) if row else None

    async def get_latest(
        self, session: AsyncSession, *, target_id: str | None = None
    ) -> TargetVersion | None:
        if target_id is None:
            result = await session.execute(
                sa.text(
                    f"SELECT {_COLS} FROM target_versions"  # noqa: S608
                    " ORDER BY deployed_at DESC LIMIT 1"
                )
            )
        else:
            result = await session.execute(
                sa.text(
                    f"SELECT {_COLS} FROM target_versions"  # noqa: S608
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
        commit_hash: str | None = None,
    ) -> TargetVersion:
        """Return the latest target_versions row, creating one if none exist.

        Used by the regression worker when the GitHub merge webhook fires
        but no target_version row has been recorded yet. version is a free-
        form string (commit SHA, semver tag, etc.). commit_hash is the
        specific merge SHA from the GitHub payload — separate from version
        so legacy callers that synthesize a version string don't conflate
        the two. Nullable.
        """
        existing = await self.get_latest(session, target_id=target_id)
        if existing is not None and existing.version == version:
            return existing
        result = await session.execute(
            sa.text(
                "INSERT INTO target_versions"  # noqa: S608
                " (target_manifest_id, target_id, version, commit_hash,"
                "  deployed_at, triggered_by)"
                " VALUES (:tmid, :tid, :ver, :ch, now(), :tb)"
                " ON CONFLICT (target_id, version) DO UPDATE"
                "   SET deployed_at = EXCLUDED.deployed_at,"
                "       commit_hash = COALESCE("
                "         EXCLUDED.commit_hash, target_versions.commit_hash"
                "       )"
                f" RETURNING {_COLS}"
            ),
            {
                "tmid": str(target_manifest_id),
                "tid": target_id,
                "ver": version,
                "ch": commit_hash,
                "tb": triggered_by,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("target_versions upsert returned no row")
        return TargetVersion.model_validate(dict(row))
