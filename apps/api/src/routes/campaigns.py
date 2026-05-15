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

import asyncio
import hashlib
import json
import time
from collections.abc import AsyncGenerator, AsyncIterator  # noqa: TC003
from datetime import UTC, datetime
from decimal import Decimal
from typing import Annotated, Any, Literal
from uuid import UUID  # noqa: TC003

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

from src.domain.campaign import Campaign, CampaignMode, CampaignStatus
from src.domain.errors import ConflictError, NotFoundError
from src.observability.context import get_request_id
from src.observability.events import log_event
from src.observability.metrics import CAMPAIGNS_HALTED_TOTAL
from src.repositories.campaigns import CampaignRepository
from src.workers.queue import (
    enqueue_orchestrator_tick,
    enqueue_red_team_execute,
    enqueue_wide_sweep,
)

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
    mode: CampaignMode = Field(
        default=CampaignMode.LIVE,
        description=(
            "'live' (default) — real billable run, counted on the dashboard."
            " 'smoke' — plumbing/CI run, excluded from dashboard stats."
        ),
    )


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
        mode=body.mode,
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
        mode=body.mode.value,
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

    Three mutually-exclusive targeting modes:

      1. Default — no targeting fields. The Orchestrator's priority
         function picks the subcategory.
      2. Subcategory pin — target_category and/or target_subcategory.
         Validated against attack_taxonomy; the Orchestrator honours
         the pin instead of running its priority function.
      3. Rerun-vuln — rerun_vulnerability_id. The route builds a
         deterministic brief seeded with the vuln's exact attack input
         and skips the Orchestrator entirely. Mutually exclusive with
         target_category / target_subcategory; mixing returns 422.

    The operator controls the budget envelope; the worker still clamps
    against its own hard caps regardless.
    """

    model_config = ConfigDict(extra="forbid")

    budget_usd: Decimal = Field(..., gt=Decimal("0"), le=Decimal("100"))
    mode: CampaignMode = Field(
        default=CampaignMode.LIVE,
        description=(
            "'live' (default) — real billable run, counted on the dashboard."
            " 'smoke' — plumbing/CI run, excluded from dashboard stats."
        ),
    )
    target_category: str | None = Field(
        default=None,
        min_length=3,
        max_length=100,
        description=(
            "Optional category-level pin. Used by the UI when the operator "
            "picks a category but no specific subcategory. Validated against "
            "attack_taxonomy.category. Ignored when target_subcategory or "
            "rerun_vulnerability_id is set."
        ),
    )
    target_subcategory: str | None = Field(
        default=None,
        min_length=3,
        max_length=100,
        description=(
            "Optional subcategory pin. If provided, must exist in "
            "attack_taxonomy. Mutually exclusive with rerun_vulnerability_id."
        ),
    )
    rerun_vulnerability_id: UUID | None = Field(
        default=None,
        description=(
            "When set, build a rerun-vuln brief seeded with the vuln's "
            "exact attack input and pin the campaign to that vuln's "
            "subcategory. Mutually exclusive with target_category / "
            "target_subcategory."
        ),
    )
    variant_count: int | None = Field(
        default=None,
        ge=1,
        le=200,
        description=(
            "Optional override for the rerun-vuln brief's variant count. "
            "Ignored for non-rerun campaigns (the Orchestrator picks)."
        ),
    )


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
    request: Request,
    _operator: Annotated[_OperatorIdentity, Depends(require_session)],
    db: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Any:
    # ------------------------------------------------------------------
    # Mutual-exclusivity: rerun_vulnerability_id cannot coexist with
    # target_category / target_subcategory. One targeting mode per call.
    # ------------------------------------------------------------------
    if body.rerun_vulnerability_id is not None and (
        body.target_category is not None or body.target_subcategory is not None
    ):
        log_event(
            "campaign_start_targeting_conflict",
            rerun_vulnerability_id=str(body.rerun_vulnerability_id),
            target_category=body.target_category or "",
            target_subcategory=body.target_subcategory or "",
            outcome="rejected",
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "type": "https://security-buddy.internal/errors/targeting-conflict",
                "title": "Conflicting Targeting Fields",
                "status": 422,
                "detail": (
                    "rerun_vulnerability_id is mutually exclusive with "
                    "target_category and target_subcategory."
                ),
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )

    # ------------------------------------------------------------------
    # Branch A: Rerun-vuln campaign — deterministic brief, no Orchestrator.
    # ------------------------------------------------------------------
    if body.rerun_vulnerability_id is not None:
        return await _start_rerun_vuln_campaign(body, request, db)

    # ------------------------------------------------------------------
    # Server-side double-submit guard.
    #
    # If a campaign with the same (mode, target_subcategory) was created
    # within the last 10 seconds and is still pending (worker has not yet
    # touched it), treat this request as a duplicate and return the
    # original campaign id. Single-operator scale; an indexed SELECT is
    # plenty.
    # ------------------------------------------------------------------
    dup = await db.execute(
        sa.text(
            "SELECT id, created_at FROM campaigns"
            " WHERE status = 'pending'"
            "   AND mode = :mode"
            "   AND target_subcategory IS NOT DISTINCT FROM :sub"
            "   AND created_at > NOW() - INTERVAL '10 seconds'"
            " ORDER BY created_at DESC"
            " LIMIT 1"
        ),
        {"mode": body.mode.value, "sub": body.target_subcategory},
    )
    dup_row = dup.mappings().first()
    if dup_row is not None:
        log_event(
            "campaign_start_deduplicated",
            campaign_id=str(dup_row["id"]),
            mode=body.mode.value,
            subcategory=body.target_subcategory or "",
            outcome="deduplicated",
        )
        return StartCampaignResponse(
            campaign_id=dup_row["id"],
            status="pending",
            enqueued_at=dup_row["created_at"],
        )

    # Validate optional category override against attack_taxonomy.
    if body.target_category is not None:
        cat_check = await db.execute(
            sa.text("SELECT 1 FROM attack_taxonomy WHERE category = :cat LIMIT 1"),
            {"cat": body.target_category},
        )
        if cat_check.first() is None:
            log_event(
                "campaign_start_invalid_category",
                category=body.target_category,
                outcome="rejected",
            )
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "type": "https://security-buddy.internal/errors/invalid-category",
                    "title": "Invalid Category",
                    "status": 400,
                    "detail": (
                        f"target_category '{body.target_category}' "
                        "is not present in attack_taxonomy."
                    ),
                    "instance": str(request.url),
                },
                media_type="application/problem+json",
            )

    # Validate optional subcategory override against attack_taxonomy.
    if body.target_subcategory is not None and not await _subcategory_exists(
        db, body.target_subcategory
    ):
        log_event(
            "campaign_start_invalid_subcategory",
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

    campaign_repo = CampaignRepository()
    campaign = await campaign_repo.create(
        db,
        target_subcategory=body.target_subcategory,
        budget_usd=body.budget_usd,
        mode=body.mode,
    )

    # Session commit happens in _get_db_session on exit.

    request_id = get_request_id() or ""
    await enqueue_orchestrator_tick(campaign.id, request_id)
    enqueued_at = datetime.now(UTC)

    log_event(
        "campaign_start_enqueued",
        campaign_id=str(campaign.id),
        budget_usd=float(body.budget_usd),
        mode=body.mode.value,
        subcategory=body.target_subcategory or "",
        outcome="enqueued",
    )

    return StartCampaignResponse(
        campaign_id=campaign.id,
        status="pending",
        enqueued_at=enqueued_at,
    )


async def _start_rerun_vuln_campaign(
    body: StartCampaignRequest,
    request: Request,
    db: AsyncSession,
) -> Any:
    """Build the deterministic rerun-vuln brief and enqueue Red Team directly.

    Orchestrator is skipped because the seed (vuln.exact_attack_input) is
    already concrete. The brief carries the synthetic seed in
    success_criteria['__rerun_seed__'] for the executor to pick up.
    """
    from src.agents.orchestrator.rerun_vuln_brief import (
        DEFAULT_RERUN_VARIANT_COUNT,
        build_rerun_brief,
    )

    assert body.rerun_vulnerability_id is not None  # narrowed by caller

    draft = await build_rerun_brief(
        session=db,
        vulnerability_id=body.rerun_vulnerability_id,
        budget_usd=body.budget_usd,
        variant_count=body.variant_count or DEFAULT_RERUN_VARIANT_COUNT,
    )
    if draft is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "type": "https://security-buddy.internal/errors/vulnerability-not-found",
                "title": "Vulnerability Not Found",
                "status": 404,
                "detail": (
                    f"Vulnerability {body.rerun_vulnerability_id} not found; "
                    "cannot build rerun campaign."
                ),
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )

    repo = CampaignRepository()
    campaign = await repo.create(
        db,
        target_subcategory=draft.target_subcategory,
        budget_usd=body.budget_usd,
        mode=body.mode,
    )
    brief = await repo.add_brief(
        db,
        campaign_id=campaign.id,
        description=draft.description,
        variant_count=draft.variant_count,
        target_subcategory=draft.target_subcategory,
        success_criteria=dict(draft.success_criteria),
        budget_usd=draft.budget_usd,
    )

    request_id = get_request_id() or ""
    await enqueue_red_team_execute(brief.id, request_id)
    enqueued_at = datetime.now(UTC)

    log_event(
        "campaign_start_rerun_enqueued",
        campaign_id=str(campaign.id),
        brief_id=str(brief.id),
        vulnerability_id=str(body.rerun_vulnerability_id),
        vuln_label=draft.seed.vuln_label,
        subcategory=draft.target_subcategory,
        variant_count=draft.variant_count,
        outcome="enqueued",
    )

    return StartCampaignResponse(
        campaign_id=campaign.id,
        status="pending",
        enqueued_at=enqueued_at,
    )


# ---------------------------------------------------------------------------
# Halt — operator-initiated graceful stop
# ---------------------------------------------------------------------------


@router.post(
    "/campaigns/{campaign_id}/halt",
    status_code=status.HTTP_200_OK,
    response_model=Campaign,
    summary="Halt an in-flight campaign",
    description=(
        "Flips the campaign row to status='halted' (with completed_at=now()) "
        "via optimistic locking. The arq worker observes the flip on its next "
        "in-loop tick and exits gracefully after the current attack lands. "
        "Only allowed from 'pending' or 'in_progress' — any other state "
        "returns 409 Conflict (RFC 7807)."
    ),
)
async def halt_campaign(
    campaign_id: UUID,
    request: Request,
    _operator: Annotated[_OperatorIdentity, Depends(require_session)],
    db: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Any:
    repo = CampaignRepository()

    current = await repo.get(db, campaign_id)
    if current is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "type": "https://security-buddy.internal/errors/campaign-not-found",
                "title": "Campaign Not Found",
                "status": 404,
                "detail": f"Campaign {campaign_id} not found.",
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )

    from_status = current.status.value
    try:
        updated = await repo.halt(
            db,
            campaign_id=campaign_id,
            expected_version_id=current.version_id,
        )
    except NotFoundError:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "type": "https://security-buddy.internal/errors/campaign-not-found",
                "title": "Campaign Not Found",
                "status": 404,
                "detail": f"Campaign {campaign_id} not found.",
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )
    except ConflictError as exc:
        log_event(
            "campaign_halt_conflict",
            campaign_id=str(campaign_id),
            from_status=from_status,
            outcome="conflict",
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "type": "https://security-buddy.internal/errors/campaign-halt-conflict",
                "title": "Campaign Cannot Be Halted",
                "status": 409,
                "detail": str(exc),
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )

    CAMPAIGNS_HALTED_TOTAL.labels(from_status=from_status).inc()
    log_event(
        "campaign_halted",
        campaign_id=str(campaign_id),
        from_status=from_status,
        outcome="halted",
    )

    return updated


# ---------------------------------------------------------------------------
# Server-Sent Events: live progress for a single campaign.
#
# Contract:
#   GET /api/v1/campaigns/{id}/events
#   Content-Type: text/event-stream
#
#   The endpoint emits one `event: update` whenever the campaign snapshot
#   hash changes (status, attacks count, verdicts count, optimistic version).
#   A `: keepalive` comment fires every 15s of silence to defeat proxy idle
#   timeouts (Railway's edge will drop streams sitting idle past their
#   timeout). When the campaign reaches a terminal status, one final
#   `event: end` is emitted and the stream closes.
#
# Why poll Postgres instead of LISTEN/NOTIFY:
#   - Single source of truth: the same SELECT the dashboard uses.
#   - No worker-side trigger or NOTIFY wiring to maintain.
#   - At 1.5s cadence + a sub-millisecond SELECT, cost is negligible for
#     the one-operator workload (THREAT_MODEL.md §1).
# ---------------------------------------------------------------------------

_TERMINAL_CAMPAIGN_STATUSES: frozenset[CampaignStatus] = frozenset(
    {
        CampaignStatus.COMPLETED,
        CampaignStatus.HALTED,
        CampaignStatus.BUDGET_EXHAUSTED,
        CampaignStatus.NO_CANDIDATES,
    }
)

_SSE_POLL_INTERVAL_SECONDS = 1.5
_SSE_HEARTBEAT_INTERVAL_SECONDS = 15.0
_SSE_MAX_STREAM_SECONDS = 60 * 30  # hard cap so a stuck campaign never holds a connection forever


async def _campaign_snapshot(session: AsyncSession, campaign_id: UUID) -> dict[str, Any] | None:
    """Return a small snapshot used to detect campaign-state changes.

    Returns None when the campaign does not exist.
    """
    result = await session.execute(
        sa.text(
            """
            SELECT
              c.status::text AS status,
              c.version_id AS version_id,
              (SELECT COUNT(*) FROM attacks a WHERE a.campaign_id = c.id) AS attacks_count,
              (
                SELECT COUNT(*)
                FROM verdicts v
                JOIN attacks a ON v.attack_id = a.id
                WHERE a.campaign_id = c.id
              ) AS verdicts_count
            FROM campaigns c
            WHERE c.id = :id
            """
        ),
        {"id": str(campaign_id)},
    )
    row = result.mappings().first()
    if row is None:
        return None
    status_str = str(row["status"])
    attacks_count = int(row["attacks_count"])
    verdicts_count = int(row["verdicts_count"])
    version_id = int(row["version_id"])
    digest_input = f"{status_str}|{version_id}|{attacks_count}|{verdicts_count}"
    return {
        "status": status_str,
        "attacks_count": attacks_count,
        "verdicts_count": verdicts_count,
        "hash": hashlib.sha256(digest_input.encode()).hexdigest()[:16],
    }


@router.get(
    "/campaigns/{campaign_id}/events",
    summary="Server-Sent Events stream of campaign progress",
)
async def campaign_events(
    campaign_id: UUID,
    request: Request,
    _operator: Annotated[_OperatorIdentity, Depends(require_session)],
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(_get_session_factory)],
) -> StreamingResponse:
    """SSE stream emitting one update per detected state change."""

    request_id = get_request_id()
    log_event(
        "campaign_sse_open",
        campaign_id=str(campaign_id),
        request_id=request_id,
        outcome="opened",
    )

    async def stream() -> AsyncIterator[bytes]:
        last_hash = ""
        last_emit = time.monotonic()
        started = time.monotonic()
        emitted_count = 0
        try:
            while True:
                if await request.is_disconnected():
                    break
                if time.monotonic() - started > _SSE_MAX_STREAM_SECONDS:
                    yield b'event: end\ndata: {"reason":"max_duration"}\n\n'
                    return

                async with factory() as session:
                    snapshot = await _campaign_snapshot(session, campaign_id)

                if snapshot is None:
                    yield b'event: error\ndata: {"error":"not_found"}\n\n'
                    return

                current_hash = snapshot["hash"]
                if current_hash != last_hash:
                    last_hash = current_hash
                    payload = json.dumps(
                        {
                            "hash": current_hash,
                            "status": snapshot["status"],
                            "attacks": snapshot["attacks_count"],
                            "verdicts": snapshot["verdicts_count"],
                        },
                        separators=(",", ":"),
                    )
                    yield f"event: update\ndata: {payload}\n\n".encode()
                    last_emit = time.monotonic()
                    emitted_count += 1
                elif time.monotonic() - last_emit > _SSE_HEARTBEAT_INTERVAL_SECONDS:
                    yield b": keepalive\n\n"
                    last_emit = time.monotonic()

                if snapshot["status"] in {s.value for s in _TERMINAL_CAMPAIGN_STATUSES}:
                    yield b'event: end\ndata: {"reason":"terminal_status"}\n\n'
                    return

                await asyncio.sleep(_SSE_POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            # Client disconnected mid-await — let it propagate after logging.
            raise
        finally:
            log_event(
                "campaign_sse_close",
                campaign_id=str(campaign_id),
                request_id=request_id,
                duration_s=round(time.monotonic() - started, 2),
                events_emitted=emitted_count,
                outcome="closed",
            )

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            # Defeat nginx/Railway buffering on event streams.
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Lightweight JSON snapshot for polling clients.
#
# The SSE endpoint above is the preferred wire for active campaign tracking,
# but the dashboard's live-status widget polls a plain JSON GET so it can
# survive proxy boundaries that drop long-lived connections (notably some
# preview/CDN edges). This route returns the same counts the SSE snapshot
# uses, plus per-status attack/verdict/vulnerability buckets the widget
# renders.
#
# Cost: a single round-trip with 4 small aggregate queries. Single-operator
# scale — negligible. Auth-gated like every other /api/v1 route.
# ---------------------------------------------------------------------------


class CampaignLiveStatusResponse(BaseModel):
    """JSON snapshot of a campaign's live progress.

    Hand-mirrored on the UI as `CampaignLiveStatus` in
    `apps/ui/src/components/live-campaign-status.tsx`. Keep them in sync.
    """

    model_config = ConfigDict(extra="forbid")

    campaign_id: UUID
    status: str
    is_terminal: bool
    attacks: dict[str, int] = Field(
        description=(
            "Attack counts bucketed by status: keys are "
            "pending_execution, awaiting_judgment, judged, plus 'total'."
        )
    )
    verdicts: dict[str, int] = Field(
        description=(
            "Verdict counts bucketed by label: keys are "
            "safe, exploit, partial, unclear, plus 'total'."
        )
    )
    vulnerabilities: dict[str, int] = Field(
        description=(
            "Vulnerability rows written for this campaign, bucketed by status."
            " Always includes 'total'."
        )
    )


@router.get(
    "/campaigns/{campaign_id}/live-status",
    response_model=CampaignLiveStatusResponse,
    summary="Lightweight JSON snapshot for client-side polling",
)
async def campaign_live_status(
    campaign_id: UUID,
    request: Request,
    _operator: Annotated[_OperatorIdentity, Depends(require_session)],
    db: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Any:
    """Return the campaign's current status + counts as a plain JSON object."""
    status_row = await db.execute(
        sa.text("SELECT status::text AS status FROM campaigns WHERE id = :id"),
        {"id": str(campaign_id)},
    )
    status_mapping = status_row.mappings().first()
    if status_mapping is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "type": "https://security-buddy.internal/errors/campaign-not-found",
                "title": "Campaign Not Found",
                "status": 404,
                "detail": f"Campaign {campaign_id} not found.",
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )
    campaign_status = str(status_mapping["status"])

    attacks_result = await db.execute(
        sa.text(
            "SELECT status::text AS status, COUNT(*)::int AS n"
            " FROM attacks"
            " WHERE campaign_id = :id"
            " GROUP BY status"
        ),
        {"id": str(campaign_id)},
    )
    attacks_buckets: dict[str, int] = {
        "pending_execution": 0,
        "awaiting_judgment": 0,
        "judged": 0,
        "total": 0,
    }
    for row in attacks_result.mappings():
        key = str(row["status"])
        count = int(row["n"])
        if key in attacks_buckets:
            attacks_buckets[key] = count
        attacks_buckets["total"] += count

    verdicts_result = await db.execute(
        sa.text(
            "SELECT v.verdict::text AS verdict, COUNT(*)::int AS n"
            " FROM verdicts v"
            " JOIN attacks a ON v.attack_id = a.id"
            " WHERE a.campaign_id = :id"
            " GROUP BY v.verdict"
        ),
        {"id": str(campaign_id)},
    )
    verdicts_buckets: dict[str, int] = {
        "safe": 0,
        "exploit": 0,
        "partial": 0,
        "unclear": 0,
        "total": 0,
    }
    for row in verdicts_result.mappings():
        key = str(row["verdict"])
        count = int(row["n"])
        if key in verdicts_buckets:
            verdicts_buckets[key] = count
        verdicts_buckets["total"] += count

    vulns_result = await db.execute(
        sa.text(
            "SELECT v.status::text AS status, COUNT(*)::int AS n"
            " FROM vulnerabilities v"
            " JOIN attacks a ON v.attack_id = a.id"
            " WHERE a.campaign_id = :id"
            " GROUP BY v.status"
        ),
        {"id": str(campaign_id)},
    )
    vulns_buckets: dict[str, int] = {"total": 0}
    for row in vulns_result.mappings():
        key = str(row["status"])
        count = int(row["n"])
        vulns_buckets[key] = count
        vulns_buckets["total"] += count

    return CampaignLiveStatusResponse(
        campaign_id=campaign_id,
        status=campaign_status,
        is_terminal=campaign_status in {s.value for s in _TERMINAL_CAMPAIGN_STATUSES},
        attacks=attacks_buckets,
        verdicts=verdicts_buckets,
        vulnerabilities=vulns_buckets,
    )


# ---------------------------------------------------------------------------
# Wide Sweep — fire N campaigns back-to-back across a breadth slice.
#
# The operator picks a breadth bucket (critical / critical_plus_high / all),
# we resolve it to a concrete subcategory list from attack_taxonomy, and
# enqueue a single arq worker job that loops through the list creating one
# campaign per subcategory with a wall-clock stagger between them.
#
# Refuses to start if any campaign is currently pending / in_progress —
# we don't pile sweeps on top of a live run (CLAUDE.md §5 "no doubling up").
# ---------------------------------------------------------------------------


_WIDE_SWEEP_PRIORITY_FILTERS: dict[str, tuple[str, ...]] = {
    "critical": ("critical",),
    "critical_plus_high": ("critical", "high"),
    "all": ("critical", "high", "medium", "low"),
}


class WideSweepRequest(BaseModel):
    """Validated body for POST /api/v1/campaigns/sweep."""

    model_config = ConfigDict(extra="forbid")

    breadth: Literal["critical", "critical_plus_high", "all"]
    budget_per_campaign_usd: Decimal = Field(
        ...,
        ge=Decimal("0.10"),
        le=Decimal("50.00"),
        description="Per-campaign budget envelope. Worker enforces independently.",
    )
    variant_count: int = Field(default=20, ge=1, le=50)
    stagger_seconds: int = Field(default=10, ge=0, le=300)


class WideSweepResponse(BaseModel):
    """202 Accepted — sweep is queued."""

    model_config = ConfigDict(extra="forbid")

    subcategories: list[str]
    subcategory_count: int
    estimated_total_usd: Decimal
    sweep_job_id: str
    enqueued_at: datetime


async def _resolve_sweep_subcategories(session: AsyncSession, breadth: str) -> list[str]:
    """Return the subcategory list for the given breadth bucket.

    Ordered deterministically (category ASC, subcategory ASC) so the
    operator sees the same sequence on repeat runs.
    """
    priorities = _WIDE_SWEEP_PRIORITY_FILTERS[breadth]
    result = await session.execute(
        sa.text(
            "SELECT subcategory FROM attack_taxonomy"
            " WHERE priority = ANY(:priorities)"
            " ORDER BY category ASC, subcategory ASC"
        ),
        {"priorities": list(priorities)},
    )
    return [str(row["subcategory"]) for row in result.mappings()]


async def _has_active_campaign(session: AsyncSession) -> bool:
    """True if any campaign is currently 'pending' or 'in_progress'."""
    result = await session.execute(
        sa.text("SELECT 1 FROM campaigns WHERE status IN ('pending', 'in_progress') LIMIT 1")
    )
    return result.first() is not None


@router.post(
    "/campaigns/sweep",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=WideSweepResponse,
    summary="Fire N campaigns back-to-back across a breadth slice of the attack surface",
    description=(
        "Resolves the requested breadth (critical | critical_plus_high | all) "
        "into a concrete subcategory list from attack_taxonomy, then enqueues a "
        "single wide_sweep worker job that creates one campaign per subcategory "
        "with a wall-clock stagger between them. Refuses with 409 if any "
        "campaign is currently pending or in_progress."
    ),
)
async def start_wide_sweep(
    body: WideSweepRequest,
    request: Request,
    _operator: Annotated[_OperatorIdentity, Depends(require_session)],
    db: Annotated[AsyncSession, Depends(_get_db_session)],
) -> Any:
    # ------------------------------------------------------------------
    # Refuse to pile a sweep on top of a live run.
    # ------------------------------------------------------------------
    if await _has_active_campaign(db):
        log_event(
            "wide_sweep_rejected_active_campaign",
            breadth=body.breadth,
            outcome="rejected",
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "type": "https://security-buddy.internal/errors/wide-sweep-active-campaign",
                "title": "Active Campaign Blocks Wide Sweep",
                "status": 409,
                "detail": (
                    "A campaign is currently pending or in_progress. Wait for "
                    "it to finish, or halt it from the dashboard, before "
                    "starting a Wide Sweep."
                ),
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )

    subcategories = await _resolve_sweep_subcategories(db, body.breadth)
    if not subcategories:
        log_event(
            "wide_sweep_rejected_no_subcategories",
            breadth=body.breadth,
            outcome="rejected",
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "type": "https://security-buddy.internal/errors/wide-sweep-no-subcategories",
                "title": "No Subcategories Match Breadth",
                "status": 400,
                "detail": (
                    f"breadth '{body.breadth}' resolved to zero subcategories in attack_taxonomy."
                ),
                "instance": str(request.url),
            },
            media_type="application/problem+json",
        )

    estimated_total = body.budget_per_campaign_usd * len(subcategories)
    bucket = int(time.time()) // 60
    request_id = get_request_id() or ""

    job_id = await enqueue_wide_sweep(
        subcategories=subcategories,
        budget_per_campaign_usd=str(body.budget_per_campaign_usd),
        variant_count=body.variant_count,
        stagger_seconds=body.stagger_seconds,
        request_id=request_id,
        bucket_epoch_minute=bucket,
    )

    enqueued_at = datetime.now(UTC)
    log_event(
        "wide_sweep_enqueued",
        breadth=body.breadth,
        subcategory_count=len(subcategories),
        budget_per_campaign_usd=float(body.budget_per_campaign_usd),
        budget_total_usd=float(estimated_total),
        sweep_job_id=job_id,
        outcome="enqueued",
    )

    return WideSweepResponse(
        subcategories=subcategories,
        subcategory_count=len(subcategories),
        estimated_total_usd=estimated_total,
        sweep_job_id=job_id,
        enqueued_at=enqueued_at,
    )
