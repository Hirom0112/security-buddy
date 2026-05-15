"""Operator-facing routes for vulnerabilities.

GET  /api/v1/vulnerabilities/{id}              — read a vulnerabilities row
POST /api/v1/vulnerabilities/{id}/decide        — confirm | dismiss
                                                 (critical-severity soft gate)

The soft-gate workflow (CLAUDE.md §"Critical-severity soft gate"):
  - Documentation Agent writes critical findings with status='draft'.
  - Confirming → status='open', triggers the Patch Agent handoff.
  - Dismissing → no-op acknowledgement (status unchanged) for now.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.domain.vulnerability import Vulnerability, VulnerabilityStatus
from src.observability.events import log_event
from src.repositories.vulnerabilities import VulnerabilityRepository
from src.workers.queue import enqueue_patch_propose

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])


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


class VulnerabilityDecisionBody(BaseModel):
    decision: Literal["confirm", "dismiss"]


@router.get("/{vulnerability_id}", response_model=Vulnerability)
async def get_vulnerability(
    vulnerability_id: UUID,
    session: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Vulnerability:
    repo = VulnerabilityRepository()
    vuln = await repo.get_by_id(session, vulnerability_id)
    if vuln is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="vulnerability not found"
        )
    return vuln


@router.post("/{vulnerability_id}/decide", response_model=Vulnerability)
async def decide_vulnerability(
    vulnerability_id: UUID,
    body: VulnerabilityDecisionBody,
    request: Request,
    session: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Vulnerability:
    repo = VulnerabilityRepository()
    vuln = await repo.get_by_id(session, vulnerability_id)
    if vuln is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="vulnerability not found"
        )

    if body.decision == "confirm":
        if vuln.status is not VulnerabilityStatus.DRAFT:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"vulnerability is already {vuln.status.value}",
            )
        updated = await repo.update_status(
            session,
            vulnerability_id=vulnerability_id,
            new_status=VulnerabilityStatus.OPEN,
        )
        if updated is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="vulnerability vanished"
            )

        request_id = getattr(request.state, "request_id", None) or "operator_action"
        await enqueue_patch_propose(updated.id, request_id)

        log_event(
            "vulnerability_confirmed",
            vulnerability_id=str(vulnerability_id),
            prior_status="draft",
            new_status="open",
            outcome="success",
        )
        return updated

    log_event(
        "vulnerability_dismissed",
        vulnerability_id=str(vulnerability_id),
        status=vuln.status.value,
        outcome="acknowledged",
    )
    return vuln
