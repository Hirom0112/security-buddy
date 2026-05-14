"""Per-attack Judge-enqueue behavior in run_executor (TODO #59 fix).

These tests cover the fundamental fix: Judge jobs are enqueued as each
attack lands in awaiting_judgment, not batched at the end of the run.
This means a crash or arq job_timeout mid-loop still leaves the queue
healthy — every attack already fired has its Judge job in Redis.

Coverage:
  1. Happy path: 3 attacks fire successfully → judge_enqueuer is called
     exactly 3 times, with the matching attack IDs.
  2. Mid-run crash: TargetClient.fire_query raises on attack #2. Attack #1
     is in awaiting_judgment and was enqueued. Attack #3 was never fired.
  3. Idempotent retry: re-running run_executor for the same brief does NOT
     re-enqueue Judge for attacks already in awaiting_judgment.

Uses respx + a captured stub enqueuer (no real Redis required for the
enqueue assertion itself).
"""

from __future__ import annotations

import os
from decimal import Decimal
from uuid import UUID

import pytest
import pytest_asyncio
import respx
from httpx import Response
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.agents.red_team.executor import run_executor
from src.agents.red_team.rate_limit import RateLimiter
from src.agents.red_team.target_client import TargetClient
from src.repositories.campaigns import CampaignRepository
from src.settings import Settings

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers (mirroring test_red_team_end_to_end.py)
# ---------------------------------------------------------------------------


def _db_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://security_buddy:security_buddy@localhost:5432/security_buddy",
    )


def _make_settings() -> Settings:
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


@pytest_asyncio.fixture
async def session_factory() -> async_sessionmaker[AsyncSession]:
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
    return RateLimiter(requests_per_second=1000.0, burst=200, campaign_attack_cap=1000)


def _openemr_base_url(settings: Settings) -> str:
    return (settings.target_openemr_url or "").rstrip("/")


def _agent_api_base_url(settings: Settings) -> str:
    return (settings.target_base_url or "").rstrip("/")


def _install_auth_mocks(router: respx.MockRouter, settings: Settings) -> None:
    """Mount the two-step auth (login + module page) mocks."""
    openemr = _openemr_base_url(settings)
    copilot_module = (settings.target_copilot_module_path or "").strip()

    router.post(f"{openemr}/interface/main/main_screen.php").mock(
        return_value=Response(
            200,
            headers={"set-cookie": "PHPSESSID=fakesessid123; Path=/; HttpOnly"},
            text="<html><body>OpenEMR Dashboard</body></html>",
        )
    )
    router.get(f"{openemr}{copilot_module}").mock(
        return_value=Response(
            200,
            text=(
                "<html><head>"
                '<script id="copilot-config" type="application/json">'
                '{"jwt":"fake.jwt.token","provider_id":"prov-chen","session_id":"sess-1"}'
                "</script></head><body>Co-Pilot</body></html>"
            ),
        )
    )


async def _create_brief(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    variant_count: int,
) -> UUID:
    """Create a campaign + brief and return the brief id."""
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
            description="Judge-enqueue test",
            variant_count=variant_count,
            target_subcategory="prompt_injection/indirect_via_upload",
            success_criteria={},
            budget_usd=Decimal("10.00"),
        )
        await setup_session.commit()
    return brief.id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_judge_enqueuer_called_once_per_attack_on_happy_path(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
) -> None:
    """A 3-attack run enqueues exactly 3 Judge jobs, one per attack."""
    brief_id = await _create_brief(session_factory, variant_count=3)

    enqueued: list[tuple[UUID, str]] = []

    async def stub_enqueuer(attack_id: UUID, request_id: str) -> None:
        enqueued.append((attack_id, request_id))

    router = respx.MockRouter(assert_all_called=False)
    _install_auth_mocks(router, settings)
    router.post(f"{_agent_api_base_url(settings)}/agent/query").mock(
        return_value=Response(
            200,
            json={
                "narrative": "Synthetic patient response.",
                "data": {},
                "citations": [],
                "errors": [],
            },
        )
    )

    with router:
        result = await run_executor(
            brief_id=brief_id,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
            judge_enqueuer=stub_enqueuer,
            request_id="req-happy-path",
        )

    assert result["completed_attack_count"] == 3
    assert result["halted_reason"] is None
    assert len(enqueued) == 3
    # All enqueued attack ids should match the awaiting_judgment ids the
    # executor reports back.
    awaiting = result["awaiting_judgment_attack_ids"]
    assert isinstance(awaiting, list)
    assert {str(a) for a, _ in enqueued} == set(awaiting)
    # Request id is propagated unchanged on every call.
    assert all(rid == "req-happy-path" for _, rid in enqueued)


@pytest.mark.asyncio
async def test_judge_enqueued_for_landed_attacks_when_fire_raises_mid_run(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If TargetClient.fire_query raises on attack #2, attack #1 must already
    have a Judge job enqueued. Attack #3 was never fired.

    This is the property TODO #59 cares about: the executor crashing mid-loop
    must not strand attacks in awaiting_judgment.
    """
    brief_id = await _create_brief(session_factory, variant_count=3)

    enqueued: list[UUID] = []

    async def stub_enqueuer(attack_id: UUID, request_id: str) -> None:
        enqueued.append(attack_id)

    # Patch TargetClient.fire_query so the second call raises RuntimeError.
    original_fire = TargetClient.fire_query
    call_counter = {"n": 0}

    async def patched_fire(self: TargetClient, **kwargs: object) -> object:
        call_counter["n"] += 1
        if call_counter["n"] == 2:
            raise RuntimeError("simulated mid-run crash on attack #2")
        return await original_fire(self, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(TargetClient, "fire_query", patched_fire)

    router = respx.MockRouter(assert_all_called=False)
    _install_auth_mocks(router, settings)
    router.post(f"{_agent_api_base_url(settings)}/agent/query").mock(
        return_value=Response(
            200,
            json={
                "narrative": "Synthetic response.",
                "data": {},
                "citations": [],
                "errors": [],
            },
        )
    )

    with router, pytest.raises(RuntimeError, match="simulated mid-run crash"):
        await run_executor(
            brief_id=brief_id,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
            judge_enqueuer=stub_enqueuer,
            request_id="req-crash",
        )

    # Attack #1 was enqueued; attack #2 raised before enqueue; attack #3
    # was never reached.
    assert len(enqueued) == 1

    # Verify DB state: exactly one row in awaiting_judgment for this brief.
    async with session_factory() as verify_session:
        from sqlalchemy import text

        row = (
            await verify_session.execute(
                text(
                    "SELECT COUNT(*) FROM attacks"
                    " WHERE brief_id = :bid AND status = 'awaiting_judgment'"
                ),
                {"bid": str(brief_id)},
            )
        ).first()
        assert row is not None
        assert int(row[0]) == 1


@pytest.mark.asyncio
async def test_judge_not_re_enqueued_on_executor_retry(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
) -> None:
    """Re-running run_executor for the same brief must not re-enqueue Judge
    for attacks already in awaiting_judgment.

    The first run fires all attacks and enqueues Judge for each. A second
    run (simulating an arq retry where the brief is not yet status=completed —
    e.g. crashed before the final brief_status update) must enqueue ZERO
    additional Judge jobs.
    """
    brief_id = await _create_brief(session_factory, variant_count=3)

    first_run_enqueued: list[UUID] = []

    async def first_enqueuer(attack_id: UUID, request_id: str) -> None:
        first_run_enqueued.append(attack_id)

    router = respx.MockRouter(assert_all_called=False)
    _install_auth_mocks(router, settings)
    router.post(f"{_agent_api_base_url(settings)}/agent/query").mock(
        return_value=Response(
            200,
            json={"narrative": "ok", "data": {}, "citations": [], "errors": []},
        )
    )

    with router:
        await run_executor(
            brief_id=brief_id,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
            judge_enqueuer=first_enqueuer,
            request_id="req-first",
        )

    assert len(first_run_enqueued) == 3

    # Simulate retry: same brief, fresh enqueuer. The executor's idempotency
    # guard at the brief-status level returns early if status=completed; that
    # case is already covered. Here we exercise the per-attack gate by
    # rolling the brief status back to in_progress so the loop re-enters
    # but every attack row is already past pending_execution.
    async with session_factory() as session:
        from sqlalchemy import text

        await session.execute(
            text("UPDATE campaign_briefs SET status = 'pending' WHERE id = :id"),
            {"id": str(brief_id)},
        )
        await session.commit()

    second_run_enqueued: list[UUID] = []

    async def second_enqueuer(attack_id: UUID, request_id: str) -> None:
        second_run_enqueued.append(attack_id)

    # Replay with the same mocks. The auth + agent endpoints are still
    # mocked, but we expect ZERO calls to /agent/query because the
    # per-attack gate skips firing for every row.
    fire_router = respx.MockRouter(assert_all_called=False)
    _install_auth_mocks(fire_router, settings)
    agent_route = fire_router.post(f"{_agent_api_base_url(settings)}/agent/query").mock(
        return_value=Response(
            200,
            json={"narrative": "ok", "data": {}, "citations": [], "errors": []},
        )
    )

    with fire_router:
        result = await run_executor(
            brief_id=brief_id,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
            judge_enqueuer=second_enqueuer,
            request_id="req-second",
        )

    # No Judge jobs enqueued on retry.
    assert second_run_enqueued == []
    # No additional target fires.
    assert agent_route.call_count == 0
    # awaiting_judgment_attack_ids is empty on the retry — nothing
    # transitioned during this invocation.
    assert result["awaiting_judgment_attack_ids"] == []
    # Total attack rows still 3.
    async with session_factory() as verify_session:
        from sqlalchemy import text

        row = (
            await verify_session.execute(
                text(
                    "SELECT COUNT(*) FROM attacks"
                    " WHERE brief_id = :bid AND status = 'awaiting_judgment'"
                ),
                {"bid": str(brief_id)},
            )
        ).first()
        assert row is not None
        assert int(row[0]) == 3


@pytest.mark.asyncio
async def test_run_executor_requires_request_id_when_enqueuer_provided(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
) -> None:
    """Passing judge_enqueuer without request_id raises ValueError up front."""

    async def noop(attack_id: UUID, request_id: str) -> None:
        return None

    with pytest.raises(ValueError, match="request_id is required"):
        await run_executor(
            brief_id=UUID("00000000-0000-0000-0000-000000000000"),
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
            judge_enqueuer=noop,
            request_id=None,
        )
