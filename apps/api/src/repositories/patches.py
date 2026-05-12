"""PatchRepository — write side for the Patch Agent.

Architectural boundary (import-linter): imports from src.domain only.

Idempotency (CLAUDE.md §5):
  Partial unique index `ix_patches_vulnerability_id_active` (migration 0005)
  prevents two open/merged patches per vulnerability. The Patch worker also
  keys arq dedup on vulnerability_id as the first line of defence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa

from src.domain.patch import Patch, PatchStatus

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

_PATCH_COLS = (
    "id, vulnerability_id, branch_name, pr_url, status, created_at,"
    " merged_at, version_id"
)


class PatchRepository:
    """Read and write rows in the patches table."""

    async def get_by_id(
        self, session: AsyncSession, patch_id: UUID
    ) -> Patch | None:
        result = await session.execute(
            sa.text(f"SELECT {_PATCH_COLS} FROM patches WHERE id = :id"),  # noqa: S608
            {"id": str(patch_id)},
        )
        row = result.mappings().first()
        return Patch.model_validate(dict(row)) if row else None

    async def get_by_vulnerability_id(
        self, session: AsyncSession, vulnerability_id: UUID
    ) -> Patch | None:
        """Return the latest non-rejected patch for the vulnerability, if any."""
        result = await session.execute(
            sa.text(
                f"SELECT {_PATCH_COLS} FROM patches"  # noqa: S608
                " WHERE vulnerability_id = :vid"
                "   AND status IN ('awaiting_human_review','merged')"
                " ORDER BY created_at DESC LIMIT 1"
            ),
            {"vid": str(vulnerability_id)},
        )
        row = result.mappings().first()
        return Patch.model_validate(dict(row)) if row else None

    async def get_by_branch_name(
        self, session: AsyncSession, branch_name: str
    ) -> Patch | None:
        result = await session.execute(
            sa.text(
                f"SELECT {_PATCH_COLS} FROM patches"  # noqa: S608
                " WHERE branch_name = :b"
                " ORDER BY created_at DESC LIMIT 1"
            ),
            {"b": branch_name},
        )
        row = result.mappings().first()
        return Patch.model_validate(dict(row)) if row else None

    async def create(
        self,
        session: AsyncSession,
        *,
        vulnerability_id: UUID,
        branch_name: str,
        pr_url: str,
    ) -> Patch:
        """Insert a patches row with status='awaiting_human_review'.

        Returns the existing active patch (awaiting_human_review or merged)
        if one already exists for the vulnerability — first-writer-wins.
        """
        existing = await self.get_by_vulnerability_id(session, vulnerability_id)
        if existing is not None:
            return existing

        result = await session.execute(
            sa.text(
                "INSERT INTO patches"  # noqa: S608
                " (vulnerability_id, branch_name, pr_url, status)"
                " VALUES (:vid, :branch, :pr_url, 'awaiting_human_review')"
                f" RETURNING {_PATCH_COLS}"
            ),
            {
                "vid": str(vulnerability_id),
                "branch": branch_name,
                "pr_url": pr_url,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("patches INSERT returned no row")
        return Patch.model_validate(dict(row))

    async def update_status(
        self,
        session: AsyncSession,
        *,
        patch_id: UUID,
        new_status: PatchStatus,
        merged_at_sql: bool = False,
    ) -> Patch | None:
        """Optimistic-locked status transition.

        merged_at_sql=True sets merged_at=now() at the same time (used by the
        merge webhook). Returns the new row or None if the patch is missing.
        """
        set_clause = "status = :s, version_id = version_id + 1"
        if merged_at_sql:
            set_clause += ", merged_at = now()"

        result = await session.execute(
            sa.text(
                f"UPDATE patches SET {set_clause}"  # noqa: S608
                f" WHERE id = :id RETURNING {_PATCH_COLS}"
            ),
            {"id": str(patch_id), "s": new_status.value},
        )
        row = result.mappings().first()
        return Patch.model_validate(dict(row)) if row else None
