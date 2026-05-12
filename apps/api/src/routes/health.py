"""Health check endpoint.

GET /healthz returns 200 always (monitoring tool convention) with a JSON
body describing the health of each subsystem: app, db, redis, langsmith.

HTTP 200 is always returned — callers inspect the JSON body to determine
overall health. This endpoint is explicitly exempt from auth (CLAUDE.md §2).
"""

from typing import Literal

import redis.asyncio as aioredis
from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from src.settings import get_settings

router = APIRouter()

SubsystemStatus = Literal["ok", "down", "unconfigured"]
OverallStatus = Literal["ok", "degraded", "down"]


class SubsystemHealth(BaseModel):
    """Health status for each platform subsystem."""

    app: SubsystemStatus
    db: SubsystemStatus
    redis: SubsystemStatus
    langsmith: SubsystemStatus


class HealthResponse(BaseModel):
    """Top-level health response."""

    status: OverallStatus
    subsystems: SubsystemHealth


async def _check_db() -> SubsystemStatus:
    """Attempt a SELECT 1 against Postgres."""
    try:
        settings = get_settings()
        engine = create_async_engine(settings.database_url, pool_size=1, max_overflow=0)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
        return "ok"
    except Exception:
        return "down"


async def _check_redis() -> SubsystemStatus:
    """Attempt a PING against Redis."""
    try:
        settings = get_settings()
        client = aioredis.from_url(settings.redis_url, socket_connect_timeout=2)
        await client.ping()
        await client.aclose()  # type: ignore[attr-defined]  # aclose() exists at runtime
        return "ok"
    except Exception:
        return "down"


def _check_langsmith() -> SubsystemStatus:
    """Determine LangSmith status without making a network call."""
    try:
        settings = get_settings()
        if settings.langsmith_disabled:
            return "unconfigured"
        # If a key is present and not DISABLED, treat as configured/ok.
        # We do not ping LangSmith to avoid cost and latency on every healthz call.
        return "ok"
    except Exception:
        return "unconfigured"


def _compute_overall(sub: SubsystemHealth) -> OverallStatus:
    """Compute top-level status from subsystem statuses."""
    statuses = [sub.app, sub.db, sub.redis, sub.langsmith]
    configured = [s for s in statuses if s != "unconfigured"]
    if not configured:
        return "down"
    if all(s == "ok" for s in configured):
        return "ok"
    if any(s == "ok" for s in configured):
        return "degraded"
    return "down"


@router.get(
    "/healthz",
    response_model=HealthResponse,
    tags=["health"],
    summary="Platform health check",
    description=(
        "Returns 200 always. Inspect 'status' and 'subsystems' in the body. "
        "Does not require authentication."
    ),
)
async def healthz() -> HealthResponse:
    """Return health of the platform and all subsystems."""
    db_status = await _check_db()
    redis_status = await _check_redis()
    langsmith_status = _check_langsmith()

    sub = SubsystemHealth(
        app="ok",
        db=db_status,
        redis=redis_status,
        langsmith=langsmith_status,
    )
    return HealthResponse(status=_compute_overall(sub), subsystems=sub)
