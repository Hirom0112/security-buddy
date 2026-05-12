"""TargetManifestRepository — data access for the target_manifests table.

Architectural boundary (import-linter):
  - This module imports from src.domain only.
  - No imports from src.agents, src.llm_client, src.routes, src.workers.

All write operations are idempotent via ON CONFLICT DO UPDATE so that
retried Alembic seed migrations or worker calls do not produce duplicate rows.
"""

from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.target_manifest import TargetManifest


class TargetManifestRepository:
    """Read and upsert rows in the target_manifests table.

    Methods receive the caller's AsyncSession so that transaction boundaries
    stay with the caller (worker or route handler).
    """

    async def get_active(
        self,
        session: AsyncSession,
    ) -> TargetManifest | None:
        """Return the single active target manifest, or None if not yet seeded.

        "Active" is defined as the row with the most-recently-seeded target_id.
        For MVP there is exactly one row ('openemr-clinical-copilot').
        """
        result = await session.execute(
            sa.text(
                "SELECT id, target_id, manifest_json, version, created_at"
                " FROM target_manifests"
                " ORDER BY created_at DESC LIMIT 1"
            )
        )
        row = result.mappings().first()
        if row is None:
            return None
        return TargetManifest.model_validate(dict(row))

    async def get_by_target_id(
        self,
        session: AsyncSession,
        target_id: str,
    ) -> TargetManifest | None:
        """Return the manifest for a specific target_id, or None."""
        result = await session.execute(
            sa.text(
                "SELECT id, target_id, manifest_json, version, created_at"
                " FROM target_manifests WHERE target_id = :target_id"
            ),
            {"target_id": target_id},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return TargetManifest.model_validate(dict(row))

    async def upsert(
        self,
        session: AsyncSession,
        *,
        target_id: str,
        manifest_json: dict[str, Any],
        version: str,
    ) -> TargetManifest:
        """Insert or update a target manifest row.

        ON CONFLICT on target_id: update manifest_json and version.
        Idempotent: retried calls with the same target_id are safe.

        Returns the resulting TargetManifest entity.
        """
        # Build the table reference for pg_insert.
        target_manifests = sa.table(
            "target_manifests",
            sa.column("id"),
            sa.column("target_id", sa.Text()),
            sa.column("manifest_json", JSONB()),
            sa.column("version", sa.Text()),
            sa.column("created_at"),
        )

        import json

        # mypy: the chain of .values().on_conflict_do_update().returning()
        # returns a ReturningInsert; assigning to `Any` lets us execute it
        # without a long type annotation chain that adds no safety here.
        from typing import Any as _Any

        stmt: _Any = (
            pg_insert(target_manifests)
            .values(
                id=sa.func.gen_random_uuid(),
                target_id=target_id,
                manifest_json=sa.cast(sa.literal(json.dumps(manifest_json)), JSONB()),
                version=version,
                created_at=sa.func.now(),
            )
            .on_conflict_do_update(
                index_elements=["target_id"],
                set_={
                    "manifest_json": sa.cast(sa.literal(json.dumps(manifest_json)), JSONB()),
                    "version": version,
                },
            )
            .returning(
                sa.column("id"),
                sa.column("target_id"),
                sa.column("manifest_json"),
                sa.column("version"),
                sa.column("created_at"),
            )
        )

        result = await session.execute(stmt)
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("upsert returned no row — this should never happen")
        return TargetManifest.model_validate(dict(row))
