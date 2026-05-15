"""HappyPathFixtureRepository — read side for the regression harness.

Architectural boundary (import-linter): imports from src.domain only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa

from src.domain.happy_path_fixture import HappyPathFixture

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession


_COLS = (
    "id, target_manifest_id, capability_name, attack_input,"
    " expected_response_shape, enabled, created_at, version_id"
)


class HappyPathFixtureRepository:
    """Read rows in the happy_path_fixtures table."""

    async def list_for_manifest(
        self,
        session: AsyncSession,
        target_manifest_id: UUID,
        *,
        enabled_only: bool = False,
    ) -> list[HappyPathFixture]:
        """Return all fixtures for a manifest, optionally filtered to enabled."""
        if enabled_only:
            result = await session.execute(
                sa.text(
                    f"SELECT {_COLS} FROM happy_path_fixtures"  # noqa: S608
                    " WHERE target_manifest_id = :tmid AND enabled = true"
                    " ORDER BY capability_name ASC"
                ),
                {"tmid": str(target_manifest_id)},
            )
        else:
            result = await session.execute(
                sa.text(
                    f"SELECT {_COLS} FROM happy_path_fixtures"  # noqa: S608
                    " WHERE target_manifest_id = :tmid"
                    " ORDER BY capability_name ASC"
                ),
                {"tmid": str(target_manifest_id)},
            )
        rows = result.mappings().all()
        return [HappyPathFixture.model_validate(dict(r)) for r in rows]

    async def get_enabled(
        self,
        session: AsyncSession,
        target_manifest_id: UUID,
    ) -> list[HappyPathFixture]:
        """Convenience wrapper — list_for_manifest with enabled_only=True."""
        return await self.list_for_manifest(session, target_manifest_id, enabled_only=True)
