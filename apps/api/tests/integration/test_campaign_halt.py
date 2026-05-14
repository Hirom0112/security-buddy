"""Integration tests for POST /api/v1/campaigns/{id}/halt and the
CampaignRepository.halt() method.

Requires a live Postgres (the docker-compose one). The route tests use a
TestClient with the app's session_factory pointed at the same DB; rows are
explicitly cleaned up at the end of each test.

Run with:
    pytest tests/integration/test_campaign_halt.py -v
"""

from __future__ import annotations

import os
from decimal import Decimal
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.agents.red_team.executor import run_executor
from src.agents.red_team.rate_limit import RateLimiter
from src.domain.campaign import CampaignStatus
from src.domain.errors import ConflictError, NotFoundError
from src.repositories.campaigns import CampaignRepository
from src.settings import Settings

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _db_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://security_buddy:security_buddy@localhost:5432/security_buddy",
    )


@pytest_asyncio.fixture
async def session() -> AsyncSession:
    """Yield a transaction-wrapped session that rolls back after the test."""
    engine = create_async_engine(_db_url(), echo=False)
    async with engine.connect() as conn:
        await conn.begin()
        nested = await conn.begin_nested()
        async_session: AsyncSession = AsyncSession(bind=conn)  # type: ignore[call-arg]
        try:
            yield async_session
        finally:
            await async_session.close()
            await nested.rollback()
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory() -> async_sessionmaker[AsyncSession]:
    """Real session factory backed by the dev Postgres. Each test cleans up
    its own rows by id (no savepoint here because the executor commits)."""
    engine = create_async_engine(_db_url(), echo=False)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    yield factory
    await engine.dispose()


campaign_repo = CampaignRepository()


# ---------------------------------------------------------------------------
# 1. Repository-level tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_halt_from_pending_succeeds(session: AsyncSession) -> None:
    """halt() on a pending campaign flips status and sets completed_at."""
    campaign = await campaign_repo.create(
        session,
        target_subcategory="prompt_injection/direct",
        budget_usd=Decimal("2.00"),
    )
    assert campaign.status == CampaignStatus.PENDING
    assert campaign.completed_at is None

    halted = await campaign_repo.halt(
        session,
        campaign_id=campaign.id,
        expected_version_id=campaign.version_id,
    )
    assert halted.status == CampaignStatus.HALTED
    assert halted.completed_at is not None
    assert halted.version_id == campaign.version_id + 1


@pytest.mark.asyncio
async def test_halt_from_in_progress_succeeds(session: AsyncSession) -> None:
    """halt() on an in_progress campaign flips to halted."""
    campaign = await campaign_repo.create(
        session,
        target_subcategory="prompt_injection/direct",
        budget_usd=Decimal("2.00"),
    )
    progressing = await campaign_repo.update_status(
        session,
        campaign_id=campaign.id,
        status=CampaignStatus.IN_PROGRESS,
        expected_version_id=campaign.version_id,
    )
    halted = await campaign_repo.halt(
        session,
        campaign_id=campaign.id,
        expected_version_id=progressing.version_id,
    )
    assert halted.status == CampaignStatus.HALTED
    assert halted.completed_at is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "from_state",
    [
        CampaignStatus.COMPLETED,
        CampaignStatus.HALTED,
        CampaignStatus.BUDGET_EXHAUSTED,
    ],
)
async def test_halt_from_terminal_state_raises_conflict(
    session: AsyncSession, from_state: CampaignStatus
) -> None:
    """halt() from any non-{pending, in_progress} state raises ConflictError."""
    campaign = await campaign_repo.create(
        session,
        target_subcategory="prompt_injection/direct",
        budget_usd=Decimal("2.00"),
    )
    advanced = await campaign_repo.update_status(
        session,
        campaign_id=campaign.id,
        status=from_state,
        expected_version_id=campaign.version_id,
    )
    with pytest.raises(ConflictError):
        await campaign_repo.halt(
            session,
            campaign_id=campaign.id,
            expected_version_id=advanced.version_id,
        )


@pytest.mark.asyncio
async def test_halt_version_conflict_raises(session: AsyncSession) -> None:
    """halt() with a stale version_id raises ConflictError."""
    campaign = await campaign_repo.create(
        session,
        target_subcategory="prompt_injection/direct",
        budget_usd=Decimal("2.00"),
    )
    # Bump the version_id out from under us.
    await campaign_repo.update_status(
        session,
        campaign_id=campaign.id,
        status=CampaignStatus.IN_PROGRESS,
        expected_version_id=campaign.version_id,
    )
    with pytest.raises(ConflictError):
        await campaign_repo.halt(
            session,
            campaign_id=campaign.id,
            expected_version_id=campaign.version_id,  # stale
        )


@pytest.mark.asyncio
async def test_halt_not_found(session: AsyncSession) -> None:
    """halt() on a non-existent campaign raises NotFoundError."""
    with pytest.raises(NotFoundError):
        await campaign_repo.halt(
            session,
            campaign_id=uuid4(),
            expected_version_id=1,
        )


# ---------------------------------------------------------------------------
# 2. Route-level tests (FastAPI TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture()
def env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "DATABASE_URL",
        os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://security_buddy:security_buddy@localhost:5432/security_buddy",
        ),
    )
    monkeypatch.setenv("REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("LANGSMITH_API_KEY", "DISABLED")
    monkeypatch.setenv("LANGSMITH_PROJECT", "test")
    monkeypatch.setenv("SESSION_SECRET", "a" * 64)

    from src import settings as settings_module

    settings_module.get_settings.cache_clear()
    yield
    settings_module.get_settings.cache_clear()


@pytest.fixture()
def route_client(
    env_vars: None,
    session_factory: async_sessionmaker[AsyncSession],
) -> TestClient:
    from src.main import app

    # Pre-seed session_factory on app.state — lifespan would normally do this,
    # but TestClient enters lifespan via the context-manager form. Setting it
    # directly here keeps the test contained.
    app.state.session_factory = session_factory
    return TestClient(app, raise_server_exceptions=False)


async def _create_campaign(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    status_after_create: CampaignStatus | None = None,
) -> tuple[str, int]:
    """Create a campaign on a fresh engine (so it's not tied to a connection
    that TestClient will later borrow). Returns (campaign_id, version_id)."""
    engine = create_async_engine(_db_url(), echo=False)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    try:
        async with factory() as s:
            c = await campaign_repo.create(
                s,
                target_subcategory="prompt_injection/direct",
                budget_usd=Decimal("2.00"),
            )
            cid = str(c.id)
            version = c.version_id
            if status_after_create is not None:
                advanced = await campaign_repo.update_status(
                    s,
                    campaign_id=c.id,
                    status=status_after_create,
                    expected_version_id=version,
                )
                version = advanced.version_id
            await s.commit()
        return cid, version
    finally:
        await engine.dispose()


async def _delete_campaign(
    session_factory: async_sessionmaker[AsyncSession], cid: str
) -> None:
    # Use a fresh engine so cleanup is not tied to a connection that may
    # have been left mid-operation by a TestClient-driven request loop.
    engine = create_async_engine(_db_url(), echo=False)
    try:
        async with engine.connect() as conn:
            await conn.execute(
                sa_text("DELETE FROM campaigns WHERE id = :id"), {"id": cid}
            )
            await conn.commit()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_route_halt_pending_returns_200(
    route_client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    cid, _ = await _create_campaign(session_factory)
    try:
        resp = route_client.post(f"/api/v1/campaigns/{cid}/halt")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["id"] == cid
        assert body["status"] == "halted"
        assert body["completed_at"] is not None

        # Verify the row in the DB via a fresh engine.
        verify_engine = create_async_engine(_db_url(), echo=False)
        try:
            async with verify_engine.connect() as conn:
                row = (
                    await conn.execute(
                        sa_text(
                            "SELECT status, completed_at FROM campaigns WHERE id = :id"
                        ),
                        {"id": cid},
                    )
                ).mappings().first()
                assert row is not None
                assert row["status"] == "halted"
                assert row["completed_at"] is not None
        finally:
            await verify_engine.dispose()
    finally:
        await _delete_campaign(session_factory, cid)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_state",
    [CampaignStatus.COMPLETED, CampaignStatus.HALTED, CampaignStatus.BUDGET_EXHAUSTED],
)
async def test_route_halt_terminal_state_returns_409(
    route_client: TestClient,
    session_factory: async_sessionmaker[AsyncSession],
    terminal_state: CampaignStatus,
) -> None:
    cid, _ = await _create_campaign(
        session_factory, status_after_create=terminal_state
    )
    try:
        resp = route_client.post(f"/api/v1/campaigns/{cid}/halt")
        assert resp.status_code == 409, resp.text
        assert resp.headers["content-type"].startswith("application/problem+json")
        body = resp.json()
        assert body["status"] == 409
        assert "detail" in body and isinstance(body["detail"], str)
    finally:
        await _delete_campaign(session_factory, cid)


@pytest.mark.asyncio
async def test_route_halt_not_found_returns_404(route_client: TestClient) -> None:
    resp = route_client.post(f"/api/v1/campaigns/{uuid4()}/halt")
    assert resp.status_code == 404, resp.text
    assert resp.headers["content-type"].startswith("application/problem+json")


# ---------------------------------------------------------------------------
# 3. In-loop guard test (executor observes the flipped status)
# ---------------------------------------------------------------------------


def _make_settings_stub() -> Settings:
    return Settings(
        database_url=_db_url(),
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        openrouter_api_key="stub",
        langsmith_api_key="DISABLED",
        langsmith_project="test",
        session_secret="a" * 32,
        target_base_url="https://example.invalid",
        target_openemr_url="https://example.invalid",
        target_copilot_module_path="/x",
        target_login_user="u",
        target_login_password="p",
    )


@pytest.mark.asyncio
async def test_executor_in_loop_guard_exits_on_halt(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After attack N lands, the executor checks campaign.status and exits
    gracefully when it sees HALTED — no further attacks fire."""
    import respx
    from httpx import Response

    settings = _make_settings_stub()

    # Create a campaign + brief with a small variant count so we can halt
    # between iterations.
    async with session_factory() as s:
        campaign = await campaign_repo.create(
            s,
            target_subcategory="prompt_injection/indirect_via_upload",
            budget_usd=Decimal("5.00"),
        )
        brief = await campaign_repo.add_brief(
            s,
            campaign_id=campaign.id,
            description="Halt-guard test brief",
            variant_count=5,
            target_subcategory="prompt_injection/indirect_via_upload",
            success_criteria={},
            budget_usd=Decimal("5.00"),
        )
        await s.commit()

    cid = str(campaign.id)
    try:
        # Mock target endpoints. Each /agent/query response flips the campaign
        # to HALTED so the next-iteration guard fires.
        router = respx.MockRouter(assert_all_called=False)
        openemr = settings.target_openemr_url.rstrip("/")
        agent_api = settings.target_base_url.rstrip("/")
        router.post(f"{openemr}/interface/main/main_screen.php").mock(
            return_value=Response(
                200,
                headers={"set-cookie": "PHPSESSID=x; Path=/; HttpOnly"},
                text="<html></html>",
            )
        )
        router.get(f"{openemr}{settings.target_copilot_module_path}").mock(
            return_value=Response(
                200,
                text=(
                    "<html><head>"
                    '<script id="copilot-config" type="application/json">'
                    '{"jwt":"j","provider_id":"p","session_id":"s"}'
                    "</script></head></html>"
                ),
            )
        )

        halt_triggered = {"done": False}

        async def _agent_handler(request: object) -> Response:
            # On the first /agent/query response, flip the campaign to HALTED.
            if not halt_triggered["done"]:
                async with session_factory() as halt_session:
                    fresh = await campaign_repo.get(halt_session, campaign.id)
                    assert fresh is not None
                    await campaign_repo.halt(
                        halt_session,
                        campaign_id=campaign.id,
                        expected_version_id=fresh.version_id,
                    )
                    await halt_session.commit()
                halt_triggered["done"] = True
            return Response(
                200,
                json={
                    "narrative": "ok",
                    "data": {},
                    "citations": [],
                    "errors": [],
                },
            )

        router.post(f"{agent_api}/agent/query").mock(side_effect=_agent_handler)

        rate_limiter = RateLimiter(
            requests_per_second=1000.0, burst=200, campaign_attack_cap=1000
        )

        with router:
            result = await run_executor(
                brief_id=brief.id,
                session_factory=session_factory,
                settings=settings,
                rate_limiter=rate_limiter,
            )

        # The first attack should complete; subsequent iterations exit via the
        # halt guard. Exact count depends on when respx side_effect resolves,
        # but it must be strictly less than the requested 5.
        assert result["halted_reason"] == "operator_halt"
        assert isinstance(result["completed_attack_count"], int)
        assert 0 < result["completed_attack_count"] < 5

        # DB row remains halted (executor must not overwrite it to COMPLETED).
        async with session_factory() as verify:
            row = (
                await verify.execute(
                    sa_text("SELECT status FROM campaigns WHERE id = :id"),
                    {"id": cid},
                )
            ).mappings().first()
            assert row is not None
            assert row["status"] == "halted"
    finally:
        # Clean up — delete attacks first (FK), then brief, then campaign.
        async with session_factory() as cleanup:
            await cleanup.execute(
                sa_text("DELETE FROM attacks WHERE campaign_id = :id"),
                {"id": cid},
            )
            await cleanup.execute(
                sa_text("DELETE FROM campaign_briefs WHERE campaign_id = :id"),
                {"id": cid},
            )
            await cleanup.execute(
                sa_text("DELETE FROM campaigns WHERE id = :id"),
                {"id": cid},
            )
            await cleanup.commit()
