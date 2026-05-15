"""Operator-facing routes for vulnerabilities.

GET  /api/v1/vulnerabilities/{id}              — read a vulnerabilities row
POST /api/v1/vulnerabilities/{id}/decide        — confirm | dismiss
                                                 (critical-severity soft gate)

The soft-gate workflow (CLAUDE.md §"Critical-severity soft gate"):
  - Documentation Agent writes critical findings with status='draft'.
  - Confirming → status='open', triggers the Patch Agent handoff.
  - Dismissing → status unchanged, but a durable audit entry is appended
    to vulnerabilities.notes (operator timestamp + reason). Dismiss
    requires a non-empty reason (>= 4 chars) so the trail is meaningful.
"""

from __future__ import annotations

# NOTE: Pydantic 2.13 forward-ref resolution requires UUID, AsyncSession,
# AsyncGenerator, and async_sessionmaker at runtime in this module — they
# back FastAPI path params / DI dependencies. Do not move them into a
# TYPE_CHECKING block (see commit db36f84).
from collections.abc import AsyncGenerator  # noqa: TC003
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID  # noqa: TC003

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

from src.domain.vulnerability import Vulnerability, VulnerabilityStatus
from src.observability.events import log_event
from src.repositories.regression_runs import RegressionRunRepository
from src.repositories.vulnerabilities import VulnerabilityRepository
from src.workers.queue import enqueue_patch_propose, enqueue_rerun_single_vulnerability

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])


async def _get_session_factory(
    request: Request,
) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    return factory


async def _get_db_session(
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(_get_session_factory)],
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
    # Required when decision == "dismiss"; cross-field check enforced below.
    reason: str | None = Field(default=None, max_length=2000)


@router.get("/{vulnerability_id}", response_model=Vulnerability)
async def get_vulnerability(
    vulnerability_id: UUID,
    session: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Vulnerability:
    repo = VulnerabilityRepository()
    vuln = await repo.get_by_id(session, vulnerability_id)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="vulnerability not found")
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
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="vulnerability not found")

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

    # decision == "dismiss"
    reason = (body.reason or "").strip()
    if len(reason) < 4:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="dismiss requires a non-empty reason (min 4 chars)",
        )

    note = {
        "at": datetime.now(UTC).isoformat(),
        "actor": "operator",
        "action": "dismiss",
        "reason": reason,
    }
    updated = await repo.append_note(
        session,
        vulnerability_id=vulnerability_id,
        note=note,
        expected_version_id=vuln.version_id,
    )
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="vulnerability was modified concurrently; reload and retry",
        )

    log_event(
        "vulnerability_dismissed",
        vulnerability_id=str(vulnerability_id),
        status=updated.status.value,
        reason_len=len(reason),
        outcome="recorded",
    )
    return updated


# ---------------------------------------------------------------------------
# POST /api/v1/vulnerabilities/{id}/rerun
#
# Operator-triggered single-vuln replay. Reuses the harness pipeline (live
# target + Judge) via the rerun_single_vulnerability arq job. Idempotency:
# the queue helper buckets the job_id by minute so double-clicks collapse.
# An "in-flight" 409 is raised when the most recent operator_rerun row for
# this vuln has started within the last _RERUN_IN_FLIGHT_SECONDS.
# ---------------------------------------------------------------------------

_RERUN_IN_FLIGHT_SECONDS = 60
_RERUN_BUCKET_SECONDS = 60


class RerunResponse(BaseModel):
    vulnerability_id: UUID
    job_id: str
    enqueued_at: datetime


@router.post(
    "/{vulnerability_id}/rerun",
    response_model=RerunResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def rerun_vulnerability(
    vulnerability_id: UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(_get_db_session)],
    replays: Annotated[int, Query(ge=1, le=5)] = 1,
) -> RerunResponse:
    """Re-run the original attack for a vulnerability against the live target.

    202 — job enqueued; the UI polls regression_runs for the result.
    404 — vulnerability not found.
    409 — vuln is in 'draft' (confirm first) or a rerun is already in flight.
    """
    vuln_repo = VulnerabilityRepository()
    vuln = await vuln_repo.get_by_id(session, vulnerability_id)
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="vulnerability not found")

    if vuln.status is VulnerabilityStatus.DRAFT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="vulnerability is draft; confirm or dismiss it before re-running",
        )

    # In-flight check: most-recent operator_rerun row started within the
    # last minute is treated as in-flight (the arq job hasn't yet written
    # its row — we use this as a defensive window on top of the job_id
    # dedup below).
    run_repo = RegressionRunRepository()
    recent = await run_repo.list_for_vulnerability(session, vulnerability_id, limit=1)
    if recent:
        latest = recent[0]
        triggered_by = latest.triggered_by or ""
        age_seconds = (datetime.now(UTC) - latest.started_at).total_seconds()
        if triggered_by.startswith("operator_rerun:") and age_seconds < _RERUN_IN_FLIGHT_SECONDS:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="a rerun is already in flight for this vulnerability",
            )

    request_id = getattr(request.state, "request_id", None) or "operator_action"
    now = datetime.now(UTC)
    bucket = int(now.timestamp()) // _RERUN_BUCKET_SECONDS
    job_id = await enqueue_rerun_single_vulnerability(
        vulnerability_id,
        request_id,
        replays=replays,
        bucket_epoch_seconds=bucket,
    )

    log_event(
        "vulnerability_rerun_enqueued",
        vulnerability_id=str(vulnerability_id),
        replays=replays,
        job_id=job_id,
        outcome="enqueued",
    )

    return RerunResponse(
        vulnerability_id=vulnerability_id,
        job_id=job_id,
        enqueued_at=now,
    )


# ---------------------------------------------------------------------------
# List vulnerabilities (UI dropdown population).
#
# Used by the Start Campaign modal's "Re-attack regressed vuln" mode to
# enumerate candidate vulns. Default filter is regressed + unstable since
# those are the only states where a rerun is meaningful.
# ---------------------------------------------------------------------------


class VulnerabilitySummary(BaseModel):
    """Compact row for the rerun dropdown."""

    id: UUID
    vuln_id: str
    title: str
    status: VulnerabilityStatus
    severity: str
    subcategory: str


class VulnerabilityListResponse(BaseModel):
    items: list[VulnerabilitySummary]
    total: int


@router.get("", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    session: Annotated[AsyncSession, Depends(_get_db_session)],
    status_filter: Annotated[
        str,
        Query(
            alias="status",
            description=(
                "Comma-separated status filter, e.g. 'regressed,unstable'. "
                "Defaults to the rerun-candidate set."
            ),
        ),
    ] = "regressed,unstable",
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> VulnerabilityListResponse:
    """Return vulnerabilities matching the status filter, joined with subcategory."""
    raw_statuses = [s.strip() for s in status_filter.split(",") if s.strip()]
    valid: list[str] = []
    for s in raw_statuses:
        try:
            valid.append(VulnerabilityStatus(s).value)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"invalid status filter: {s}",
            ) from None
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="status filter cannot be empty",
        )

    result = await session.execute(
        sa.text(
            """
            SELECT v.id            AS id,
                   v.vuln_id       AS vuln_id,
                   v.title         AS title,
                   v.status        AS status,
                   v.severity      AS severity,
                   a.subcategory   AS subcategory
            FROM vulnerabilities v
            JOIN attacks a ON a.id = v.attack_id
            WHERE v.status = ANY(:statuses)
            ORDER BY v.created_at DESC
            LIMIT :limit
            """
        ),
        {"statuses": valid, "limit": limit},
    )
    rows: list[dict[str, Any]] = [dict(r) for r in result.mappings().all()]
    items = [VulnerabilitySummary.model_validate(r) for r in rows]
    return VulnerabilityListResponse(items=items, total=len(items))
