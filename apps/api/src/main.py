"""FastAPI application entry point.

Wires together:
  - RequestIdMiddleware (per-request ContextVar)
  - slowapi rate limiting (100 req/min per IP)
  - Global RFC 7807 exception handlers
  - /healthz route (unauthenticated)
  - /metrics endpoint (prometheus_client ASGI app)
  - Startup/shutdown lifecycle (asyncpg pool, Redis pool)

All endpoints require authentication except GET /healthz and POST /api/v1/auth/login.
The auth dependency is stubbed here and replaced with a real implementation in Slice 1.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from src.db.engine import create_engine, create_session_factory
from src.domain.errors import DomainError
from src.observability.middleware import RequestIdMiddleware
from src.routes.campaigns import router as campaigns_router
from src.routes.health import router as health_router
from src.routes.webhooks import router as webhooks_router
from src.settings import Settings, get_settings

# ---------------------------------------------------------------------------
# Application state container (attached to app.state)
# ---------------------------------------------------------------------------


class AppState:
    """Mutable app state stored on app.state for sharing across requests."""

    engine: AsyncEngine
    session_factory: async_sessionmaker[AsyncSession]
    redis: aioredis.Redis  # type: ignore[type-arg]


# ---------------------------------------------------------------------------
# Lifespan context manager (replaces deprecated on_event)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Create and tear down shared resources for the application lifecycle."""
    settings: Settings = get_settings()

    # --- Startup ---
    engine = create_engine(settings)
    session_factory = create_session_factory(engine)
    redis_client: aioredis.Redis = aioredis.from_url(  # type: ignore[type-arg]
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )

    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.redis = redis_client

    yield

    # --- Shutdown ---
    await redis_client.aclose()  # type: ignore[attr-defined]  # aclose() exists at runtime
    await engine.dispose()


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Security Buddy API",
    description="Adversarial evaluation platform for AI-assisted clinical workflows.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Attach rate limiter state (required by slowapi)
app.state.limiter = limiter

# Middleware (order matters — outermost first)
app.add_middleware(RequestIdMiddleware)

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


def _problem_detail(
    status_code: int,
    title: str,
    detail: str,
    instance: str | None = None,
) -> JSONResponse:
    """Return an RFC 7807 Problem Details response.

    Never includes str(exception) or raw stack traces (CLAUDE.md §9).
    """
    body = {
        "type": f"https://security-buddy.internal/errors/{title.lower().replace(' ', '-')}",
        "title": title,
        "status": status_code,
        "detail": detail,
    }
    if instance:
        body["instance"] = instance
    return JSONResponse(
        status_code=status_code,
        content=body,
        media_type="application/problem+json",
    )


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return _rate_limit_exceeded_handler(request, exc)  # type: ignore[return-value]


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Return RFC 7807 for Pydantic v2 validation errors."""
    return _problem_detail(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        title="Unprocessable Entity",
        detail="Request body failed schema validation.",
        instance=str(request.url),
    )


@app.exception_handler(DomainError)
async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
    """Map domain errors to RFC 7807 responses."""
    return _problem_detail(
        status_code=exc.http_status,
        title=type(exc).__name__,
        detail=exc.message,
        instance=str(request.url),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all: return 500 without leaking internal details (CLAUDE.md §9)."""
    return _problem_detail(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        title="Internal Server Error",
        detail="An unexpected error occurred. Check server logs for details.",
        instance=str(request.url),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

app.include_router(health_router)
app.include_router(campaigns_router)
app.include_router(webhooks_router)

# Prometheus metrics endpoint (no auth — monitoring infrastructure needs it)
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# TODO(slice-1): include auth router at /api/v1/auth/login (unauthenticated)
# TODO(slice-7): replace require_session stub with real session auth
