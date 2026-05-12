"""POST /api/v1/campaigns endpoint.

Creates a campaign + brief, then enqueues an arq job for the Red Team
execution loop.

Security:
  - All endpoints except /healthz and /api/v1/auth/login require auth.
    A stub `require_session` dep is used here (Slice 1); replaced in Slice 7.
  - No secrets in logs. log_event() handles redaction.
  - RFC 7807 problem details for 400 errors.

Import-linter:
  - routes/ may import anything except workers/ handler modules.
  - The only arq surface imported is workers.queue (the enqueue helper),
    not workers.red_team_worker directly.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator  # noqa: TC003
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any
from uuid import UUID  # noqa: TC003

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

from src.observability.context import get_request_id
from src.observability.events import log_event
from src.repositories.campaigns import CampaignRepository
from src.workers.queue import enqueue_orchestrator_tick, enqueue_red_team_execute

router = APIRouter(prefix="/api/v1", tags=["campaigns"])


# ---------------------------------------------------------------------------
# Auth stub
# TODO(slice-7): replace with real session auth tied to the UI cookie.
# ---------------------------------------------------------------------------


class _OperatorIdentity(BaseModel):
    """Stub operator identity — single-user platform (CLAUDE.md §2)."""

    user: str = "operator"


async def require_session() -> _OperatorIdentity:
    """Auth dependency stub for Slice 1.

    TODO(slice-7): real session auth tied to UI cookie (httpOnly + Secure +
    SameSite=Strict). For now every call is permitted so the Red Team loop
    can be triggered from the command line / curl.
    """
    return _OperatorIdentity()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateCampaignRequest(BaseModel):
    """Validated request body for POST /api/v1/campaigns."""

    model_config = ConfigDict(extra="forbid")

    target_subcategory: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=10, max_length=2000)
    variant_count: int = Field(..., ge=1, le=200)
    budget_usd: Decimal = Field(..., gt=Decimal("0"), le=Decimal("100"))
    success_criteria: dict[str, str] = Field(default_factory=dict)


class CreateCampaignResponse(BaseModel):
    """202 Accepted response body for POST /api/v1/campaigns."""

    campaign_id: UUID
    brief_id: UUID
    status: str
    enqueued_at: datetime


# ---------------------------------------------------------------------------
# DB dependency (session from app.state.session_factory)
# ---------------------------------------------------------------------------


async def _get_session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    return factory


async def _get_db_session(
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(_get_session_factory)],
) -> AsyncGenerator[AsyncSession, None]:
    """Yield a DB session for the request lifetime."""
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ---------------------------------------------------------------------------
# Taxonomy lookup
# ---------------------------------------------------------------------------


async def _subcategory_exists(session: AsyncSession, subcategory: str) -> bool:
    """Return True if the subcategory is present in attack_taxonomy."""
    result = await session.execute(
        sa.text("SELECT 1 FROM attack_taxonomy WHERE subcategory = :sub LIMIT 1"),
        {"sub": subcategory},
    )
    return result.first() is not None


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.post(
    "/campaigns",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=CreateCampaignResponse,
    summary="Create a campaign and enqueue Red Team execution",
    description=(
        "Creates a campaign + brief in Postgres, then enqueues an arq job "
        "to run the Red Team execution loop. Returns 202 Accepted immediately."
    ),
)
async def create_campaign(
    body: CreateCampaignRequest,
    request: Request,
    _operator: Annotated[_OperatorIdentity, Depends(require_session)],
    db: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Any:
    """Create a campaign brief and enqueue the Red Team job."""
    # ------------------------------------------------------------------
    # Validate target_subcategory against attack_taxonomy.
    # ------------------------------------------------------------------
    if not await _subcategory_exists(db, body.target_subcategory):
        log_event(
            "campaign_create_invalid_subcategory",
            subcategory=body.target_subcategory,
            outcome="rejected",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "type": "https://security-buddy.internal/errors/invalid-subcategory",
                "title": "Invalid Subcategory",
                "status": 400,
                "detail": (
                    f"target_subcategory '{body.target_subcategory}' "
                    "is not present in attack_taxonomy."
                ),
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )

    # ------------------------------------------------------------------
    # Create campaign + brief in a single transaction.
    # ------------------------------------------------------------------
    campaign_repo = CampaignRepository()

    campaign = await campaign_repo.create(
        db,
        target_subcategory=body.target_subcategory,
        budget_usd=body.budget_usd,
    )

    brief = await campaign_repo.add_brief(
        db,
        campaign_id=campaign.id,
        description=body.description,
        variant_count=body.variant_count,
        target_subcategory=body.target_subcategory,
        success_criteria=dict(body.success_criteria),
        budget_usd=body.budget_usd,
    )

    # Session commit happens in _get_db_session on exit.

    # ------------------------------------------------------------------
    # Enqueue arq job — after commit so the worker sees the rows.
    # ------------------------------------------------------------------
    request_id = get_request_id() or ""
    await enqueue_red_team_execute(brief.id, request_id)

    enqueued_at = datetime.now(UTC)

    log_event(
        "campaign_created",
        campaign_id=str(campaign.id),
        brief_id=str(brief.id),
        subcategory=body.target_subcategory,
        variant_count=body.variant_count,
        outcome="enqueued",
    )

    return CreateCampaignResponse(
        campaign_id=campaign.id,
        brief_id=brief.id,
        status="pending",
        enqueued_at=enqueued_at,
    )


# ---------------------------------------------------------------------------
# Orchestrator-driven start (Slice 3)
# ---------------------------------------------------------------------------


class StartCampaignRequest(BaseModel):
    """Validated body for POST /api/v1/campaigns/start.

    No target_subcategory: the Orchestrator's priority function picks one.
    The operator only controls the budget envelope; everything else is
    coverage-driven.
    """

    model_config = ConfigDict(extra="forbid")

    budget_usd: Decimal = Field(..., gt=Decimal("0"), le=Decimal("100"))


class StartCampaignResponse(BaseModel):
    """202 Accepted response — orchestrator job is queued but not yet run."""

    campaign_id: UUID
    status: str
    enqueued_at: datetime


@router.post(
    "/campaigns/start",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=StartCampaignResponse,
    summary="Create an empty campaign and let the Orchestrator pick the subcategory",
    description=(
        "Slice 3 entry point. Creates a pending campaign with no "
        "target_subcategory, enqueues orchestrator.tick(campaign_id). The "
        "Orchestrator's priority function selects the subcategory, the LLM "
        "frames the brief (with deterministic fallback), and the Red Team "
        "job is enqueued from the orchestrator worker."
    ),
)
async def start_campaign(
    body: StartCampaignRequest,
    _operator: Annotated[_OperatorIdentity, Depends(require_session)],
    db: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Any:
    campaign_repo = CampaignRepository()
    campaign = await campaign_repo.create(
        db,
        target_subcategory=None,
        budget_usd=body.budget_usd,
    )

    # Session commit happens in _get_db_session on exit.

    request_id = get_request_id() or ""
    await enqueue_orchestrator_tick(campaign.id, request_id)
    enqueued_at = datetime.now(UTC)

    log_event(
        "campaign_start_enqueued",
        campaign_id=str(campaign.id),
        budget_usd=float(body.budget_usd),
        outcome="enqueued",
    )

    return StartCampaignResponse(
        campaign_id=campaign.id,
        status="pending",
        enqueued_at=enqueued_at,
    )
