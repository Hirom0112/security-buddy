"""Operator-facing routes for the Patch Agent's pull requests.

Two endpoints:
  - GET  /api/v1/patches/{patch_id}              — read a patches row
  - POST /api/v1/patches/{patch_id}/review        — mark merged | rejected | ci_failed

The webhook at /webhooks/github also transitions patches.status='merged'
when a PR is merged on GitHub — this manual route exists for operator
overrides (rejecting a PR that GitHub closed without merge, marking
ci_failed when CI flips red, etc.).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from src.domain.patch import Patch, PatchStatus
from src.observability.events import log_event
from src.repositories.patches import PatchRepository

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

router = APIRouter(prefix="/api/v1/patches", tags=["patches"])


async def _get_session_factory(
    request: Request,
) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    return factory


async def _get_db_session(
    factory: Annotated[
        async_sessionmaker[AsyncSession], Depends(_get_session_factory)
    ],
) -> AsyncGenerator[AsyncSession, None]:
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


class PatchReviewBody(BaseModel):
    """Body for POST /patches/{id}/review."""

    decision: Literal["merged", "rejected", "ci_failed"]


@router.get("/{patch_id}", response_model=Patch)
async def get_patch(
    patch_id: UUID,
    session: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Patch:
    repo = PatchRepository()
    patch = await repo.get_by_id(session, patch_id)
    if patch is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="patch not found"
        )
    return patch


@router.post("/{patch_id}/review", response_model=Patch)
async def review_patch(
    patch_id: UUID,
    body: PatchReviewBody,
    session: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Patch:
    repo = PatchRepository()
    patch = await repo.get_by_id(session, patch_id)
    if patch is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="patch not found"
        )
    if patch.status is not PatchStatus.AWAITING_HUMAN_REVIEW:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"patch is already {patch.status.value}",
        )

    new_status = PatchStatus(body.decision)
    updated = await repo.update_status(
        session,
        patch_id=patch_id,
        new_status=new_status,
        merged_at_sql=(new_status is PatchStatus.MERGED),
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="patch vanished"
        )

    log_event(
        "patch_reviewed",
        patch_id=str(patch_id),
        new_status=new_status.value,
        outcome="success",
    )
    return updated
