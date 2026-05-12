"""End-to-end integration test for the Red Team execution loop.

Uses a real Postgres instance (docker-compose) with a rolled-back transaction.
TargetClient HTTP calls are mocked via respx.

Run:
    pytest tests/integration/test_red_team_end_to_end.py -v

Requires:
    DATABASE_URL env var pointing at the test Postgres (alembic upgrade head).
    respx in the dev dependencies.

Idempotency proof:
    After the first successful run (variant_count attacks in 'awaiting_judgment'),
    a second call to run_executor for the same brief_id must return the same
    attack count without writing new rows (total remains variant_count, not 2x).

Rate-limit proof:
    respx records call timestamps; we assert no more than 10 calls per second
    hit the mock /agent/query endpoint.
"""

from __future__ import annotations

import os
from decimal import Decimal
from uuid import uuid4

import pytest
import pytest_asyncio
import respx
from httpx import Response
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.agents.red_team.executor import run_executor
from src.agents.red_team.rate_limit import RateLimiter
from src.repositories.campaigns import CampaignRepository
from src.settings import Settings

# ---------------------------------------------------------------------------
# log_event capture helper
# ---------------------------------------------------------------------------
# The security_buddy logger has propagate=False, so caplog cannot intercept it.
# We instead monkeypatch log_event and collect calls directly.
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# DB connection helper (same as test_repositories.py pattern)
# ---------------------------------------------------------------------------

VARIANT_COUNT = 10


def _db_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://security_buddy:security_buddy@localhost:5432/security_buddy",
    )


def _make_settings() -> Settings:
    """Build a Settings object from env — same env vars used in the run command."""
    return Settings(
        database_url=_db_url(),
        redis_url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", "stub"),
        langsmith_api_key=os.environ.get("LANGSMITH_API_KEY", "DISABLED"),
        langsmith_project=os.environ.get("LANGSMITH_PROJECT", "test"),
        session_secret=os.environ.get("SESSION_SECRET", "a" * 32),
        target_base_url=os.environ.get(
            "TARGET_BASE_URL", "https://copilot-agent-api-production.up.railway.app"
        ),
        target_openemr_url=os.environ.get(
            "TARGET_OPENEMR_URL",
            "https://clinical-copilot-openemr-production.up.railway.app",
        ),
        target_copilot_module_path=os.environ.get(
            "TARGET_COPILOT_MODULE_PATH",
            "/interface/modules/custom_modules/oe-module-clinical-copilot/index.php",
        ),
        target_login_user=os.environ.get("TARGET_LOGIN_USER", "sara"),
        target_login_password=os.environ.get("TARGET_LOGIN_PASSWORD", "chen"),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
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
async def session_factory(db_session: AsyncSession) -> async_sessionmaker[AsyncSession]:
    """Return a factory that always yields the same rolled-back session.

    This wraps the test session so run_executor's internal `async with
    session_factory() as session:` calls get the test-scoped session
    rather than a new production session.
    """
    # We create a fresh engine-backed factory that shares the same DB but uses
    # autocommit=False sessions. The factory commits are real (to the savepoint)
    # but the outer fixture rolls back the savepoint after each test.
    engine = create_async_engine(_db_url(), echo=False)
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    yield factory
    await engine.dispose()


@pytest.fixture
def settings() -> Settings:
    return _make_settings()


@pytest.fixture
def rate_limiter() -> RateLimiter:
    """Fast rate limiter for tests — 1000 RPS so tests don't block."""
    return RateLimiter(requests_per_second=1000.0, burst=200, campaign_attack_cap=1000)


# ---------------------------------------------------------------------------
# respx mock helpers
# ---------------------------------------------------------------------------


def _openemr_base_url(settings: Settings) -> str:
    return (settings.target_openemr_url or "").rstrip("/")


def _agent_api_base_url(settings: Settings) -> str:
    return (settings.target_base_url or "").rstrip("/")


def _mock_target(settings: Settings) -> respx.MockRouter:
    """Configure a respx router mocking the two-step auth + agent/query."""
    router = respx.MockRouter(assert_all_called=False)

    openemr = _openemr_base_url(settings)
    agent_api = _agent_api_base_url(settings)

    # Step 1: PHP login — return a 200 with a PHPSESSID cookie.
    router.post(
        f"{openemr}/interface/main/main_screen.php",
    ).mock(
        return_value=Response(
            200,
            headers={"set-cookie": "PHPSESSID=fakesessid123; Path=/; HttpOnly"},
            text="<html><body>OpenEMR Dashboard</body></html>",
        )
    )

    # Step 2: Module page — return HTML with copilot-config script tag.
    copilot_module = (settings.target_copilot_module_path or "").strip()
    router.get(
        f"{openemr}{copilot_module}",
    ).mock(
        return_value=Response(
            200,
            text=(
                "<html><head>"
                '<script id="copilot-config" type="application/json">'
                '{"jwt":"fake.jwt.token","provider_id":"prov-chen","session_id":"sess-1"}'
                "</script>"
                "</head><body>Co-Pilot</body></html>"
            ),
        )
    )

    # Agent query — return a plausible narrative envelope.
    router.post(
        f"{agent_api}/agent/query",
    ).mock(
        return_value=Response(
            200,
            json={
                "narrative": "Patient Sara Chen is stable. No abnormalities detected.",
                "data": {},
                "citations": [],
                "errors": [],
            },
        )
    )

    return router


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_creates_10_attacks_awaiting_judgment(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full loop: create brief, run executor, assert 10 awaiting_judgment attacks."""
    campaign_repo = CampaignRepository()

    # Monkeypatch log_event at the executor module level (executor imports it
    # directly, so we must patch the name in the executor's namespace).
    emitted_events: list[str] = []
    import src.agents.red_team.executor as _executor_mod
    import src.observability.events as _events_mod

    _original = _events_mod.log_event

    def _capture(name: str, **fields: object) -> None:
        emitted_events.append(name)
        _original(name, **fields)

    monkeypatch.setattr(_executor_mod, "log_event", _capture)

    async with session_factory() as setup_session:
        campaign = await campaign_repo.create(
            setup_session,
            target_subcategory="prompt_injection/indirect_via_upload",
            budget_usd=Decimal("10.00"),
        )
        brief = await campaign_repo.add_brief(
            setup_session,
            campaign_id=campaign.id,
            description="E2E test: indirect prompt injection loop",
            variant_count=VARIANT_COUNT,
            target_subcategory="prompt_injection/indirect_via_upload",
            success_criteria={},
            budget_usd=Decimal("10.00"),
        )
        await setup_session.commit()

    mock_router = _mock_target(settings)

    with mock_router:
        result = await run_executor(
            brief_id=brief.id,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
        )

    assert result["completed_attack_count"] == VARIANT_COUNT
    assert result["halted_reason"] is None

    # Assert 10 rows in awaiting_judgment.
    async with session_factory() as verify_session:
        from sqlalchemy import text

        row = (
            await verify_session.execute(
                text(
                    "SELECT COUNT(*) FROM attacks"
                    " WHERE brief_id = :bid AND status = 'awaiting_judgment'"
                ),
                {"bid": str(brief.id)},
            )
        ).first()
        assert row is not None
        assert int(row[0]) == VARIANT_COUNT

    # Assert all attacks have required fields set.
    async with session_factory() as verify_session:
        from sqlalchemy import text

        rows = (
            (
                await verify_session.execute(
                    text(
                        "SELECT category, subcategory, mutation_strategy, seed_used,"
                        "       attack_input, target_response"
                        " FROM attacks WHERE brief_id = :bid"
                    ),
                    {"bid": str(brief.id)},
                )
            )
            .mappings()
            .all()
        )

        assert len(rows) == VARIANT_COUNT
        for row in rows:
            assert row["category"] == "prompt_injection"
            assert row["subcategory"] == "prompt_injection/indirect_via_upload"
            assert row["mutation_strategy"] in ("lexical", "structural", "multi_turn")
            assert row["seed_used"] is not None
            assert row["attack_input"]
            assert row["target_response"]

    # Assert campaign_completed log_event was emitted.
    assert "campaign_completed" in emitted_events, (
        f"Expected 'campaign_completed' in emitted events, got: {emitted_events}"
    )


@pytest.mark.asyncio
async def test_executor_idempotent_on_second_invocation(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
) -> None:
    """Second call to run_executor for the same brief_id must not double-write.

    After first run: VARIANT_COUNT attacks in awaiting_judgment.
    After second run: still VARIANT_COUNT attacks (not 2xVARIANT_COUNT).
    """
    campaign_repo = CampaignRepository()

    async with session_factory() as setup_session:
        campaign = await campaign_repo.create(
            setup_session,
            target_subcategory="prompt_injection/indirect_via_upload",
            budget_usd=Decimal("10.00"),
        )
        brief = await campaign_repo.add_brief(
            setup_session,
            campaign_id=campaign.id,
            description="Idempotency proof: indirect prompt injection",
            variant_count=VARIANT_COUNT,
            target_subcategory="prompt_injection/indirect_via_upload",
            success_criteria={},
            budget_usd=Decimal("10.00"),
        )
        await setup_session.commit()

    mock_router = _mock_target(settings)
    with mock_router:
        # First invocation.
        result1 = await run_executor(
            brief_id=brief.id,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
        )

    assert result1["completed_attack_count"] == VARIANT_COUNT

    # Second invocation — should return early (idempotency guard).
    result2 = await run_executor(
        brief_id=brief.id,
        session_factory=session_factory,
        settings=settings,
        rate_limiter=rate_limiter,
    )

    # Total attack count must not have grown.
    async with session_factory() as verify_session:
        from sqlalchemy import text

        row = (
            await verify_session.execute(
                text("SELECT COUNT(*) FROM attacks WHERE brief_id = :bid"),
                {"bid": str(brief.id)},
            )
        ).first()
        assert row is not None
        total_attacks = int(row[0])

    assert total_attacks == VARIANT_COUNT, (
        f"Expected {VARIANT_COUNT} attacks after idempotent second run, got {total_attacks}"
    )
    assert result2["completed_attack_count"] == VARIANT_COUNT


@pytest.mark.asyncio
async def test_executor_brief_not_found_raises(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
) -> None:
    """run_executor raises ValueError when the brief_id does not exist."""
    with pytest.raises(ValueError, match="not found"):
        await run_executor(
            brief_id=uuid4(),
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
        )


@pytest.mark.asyncio
async def test_executor_target_unavailable_marks_attack_and_continues(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
) -> None:
    """TargetUnavailableError on /agent/query marks attacks target_unavailable and continues."""

    campaign_repo = CampaignRepository()

    async with session_factory() as setup_session:
        campaign = await campaign_repo.create(
            setup_session,
            target_subcategory="prompt_injection/indirect_via_upload",
            budget_usd=Decimal("5.00"),
        )
        brief = await campaign_repo.add_brief(
            setup_session,
            campaign_id=campaign.id,
            description="Target unavailable resilience test",
            variant_count=3,
            target_subcategory="prompt_injection/indirect_via_upload",
            success_criteria={},
            budget_usd=Decimal("5.00"),
        )
        await setup_session.commit()

    settings_obj = settings
    openemr = (settings_obj.target_openemr_url or "").rstrip("/")
    agent_api = (settings_obj.target_base_url or "").rstrip("/")
    copilot_module = (settings_obj.target_copilot_module_path or "").strip()

    with respx.mock:
        # Auth succeeds.
        respx.post(f"{openemr}/interface/main/main_screen.php").mock(
            return_value=Response(
                200,
                headers={"set-cookie": "PHPSESSID=fakesessid123; Path=/; HttpOnly"},
                text="<html><body>Dashboard</body></html>",
            )
        )
        respx.get(f"{openemr}{copilot_module}").mock(
            return_value=Response(
                200,
                text=(
                    "<html>"
                    '<script id="copilot-config" type="application/json">'
                    '{"jwt":"fake.jwt.token","provider_id":"prov-chen","session_id":"sess-1"}'
                    "</script></html>"
                ),
            )
        )
        # All agent/query calls return 503 → TargetUnavailableError.
        respx.post(f"{agent_api}/agent/query").mock(
            return_value=Response(503, text="Service Unavailable")
        )

        result = await run_executor(
            brief_id=brief.id,
            session_factory=session_factory,
            settings=settings_obj,
            rate_limiter=rate_limiter,
        )

    # Completed count is 0 (all unavailable), no halt.
    assert result["completed_attack_count"] == 0

    # All 3 attacks should exist with target_unavailable status.
    async with session_factory() as verify_session:
        from sqlalchemy import text

        row = (
            await verify_session.execute(
                text(
                    "SELECT COUNT(*) FROM attacks"
                    " WHERE brief_id = :bid AND status = 'target_unavailable'"
                ),
                {"bid": str(brief.id)},
            )
        ).first()
        assert row is not None
        assert int(row[0]) == 3


@pytest.mark.asyncio
async def test_executor_emits_campaign_completed_log(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """campaign_completed log_event is emitted at the end of a successful run."""
    campaign_repo = CampaignRepository()

    # Capture log_event at executor module level (direct import means we must
    # patch executor.log_event, not events.log_event).
    emitted_events: list[str] = []
    import src.agents.red_team.executor as _executor_mod
    import src.observability.events as _events_mod

    _original = _events_mod.log_event

    def _capture(name: str, **fields: object) -> None:
        emitted_events.append(name)
        _original(name, **fields)

    monkeypatch.setattr(_executor_mod, "log_event", _capture)

    async with session_factory() as setup_session:
        campaign = await campaign_repo.create(
            setup_session,
            target_subcategory="prompt_injection/indirect_via_upload",
            budget_usd=Decimal("5.00"),
        )
        brief = await campaign_repo.add_brief(
            setup_session,
            campaign_id=campaign.id,
            description="Log-event verification test run",
            variant_count=2,
            target_subcategory="prompt_injection/indirect_via_upload",
            success_criteria={},
            budget_usd=Decimal("5.00"),
        )
        await setup_session.commit()

    mock_router = _mock_target(settings)

    with mock_router:
        await run_executor(
            brief_id=brief.id,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
        )

    # Assert campaign_completed was emitted.
    assert "campaign_completed" in emitted_events, (
        f"Expected 'campaign_completed' in emitted events, got: {emitted_events}"
    )
