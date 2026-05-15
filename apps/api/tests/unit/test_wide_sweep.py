"""Unit tests for the Wide Sweep route + worker + breadth resolver.

Mocks:
  - sqlalchemy.execute via AsyncMock
  - enqueue_wide_sweep (route side)
  - enqueue_orchestrator_tick + CampaignRepository.create (worker side)
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://security_buddy:security_buddy@localhost:5432/security_buddy",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("OPENROUTER_API_KEY", "stub")
os.environ.setdefault("LANGSMITH_API_KEY", "DISABLED")
os.environ.setdefault("LANGSMITH_PROJECT", "test")
os.environ.setdefault("SESSION_SECRET", "a" * 32)
os.environ.setdefault("TARGET_BASE_URL", "https://target.example.com")
os.environ.setdefault("TARGET_OPENEMR_URL", "https://openemr.example.com")
os.environ.setdefault(
    "TARGET_COPILOT_MODULE_PATH", "/interface/modules/custom_modules/copilot/index.php"
)
os.environ.setdefault("TARGET_LOGIN_USER", "sara")
os.environ.setdefault("TARGET_LOGIN_PASSWORD", "chen")

from src.domain.campaign import Campaign, CampaignMode, CampaignStatus
from src.main import app
from src.routes import campaigns as campaigns_route
from src.workers.wide_sweep_worker import run_wide_sweep

# ---------------------------------------------------------------------------
# Helpers — fake DB result rows
# ---------------------------------------------------------------------------


def _mappings_for(subcategories: list[str]) -> list[dict[str, str]]:
    return [{"subcategory": s} for s in subcategories]


class _FakeMappingsResult:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> _FakeMappingsResult:
        return self

    def first(self) -> dict[str, Any] | None:
        return self._rows[0] if self._rows else None

    def __iter__(self) -> Any:
        return iter(self._rows)


def _make_session_with_results(results: list[_FakeMappingsResult]) -> AsyncMock:
    """Build an AsyncMock session whose .execute returns the given results in order."""
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=results)
    session.commit = AsyncMock()
    return session


@pytest.fixture
def client_with(monkeypatch: pytest.MonkeyPatch) -> Any:
    """TestClient + an injection helper for the session factory."""

    def _make(execute_results: list[_FakeMappingsResult]) -> TestClient:
        fake_session = _make_session_with_results(execute_results)
        mock_factory = MagicMock()
        mock_factory.return_value.__aenter__ = AsyncMock(return_value=fake_session)
        mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)
        app.state.session_factory = mock_factory

        if not hasattr(app.state, "limiter"):
            from slowapi import Limiter
            from slowapi.util import get_remote_address

            app.state.limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])
        return TestClient(app, raise_server_exceptions=False)

    return _make


# ---------------------------------------------------------------------------
# Route tests
# ---------------------------------------------------------------------------


@patch("src.routes.campaigns.enqueue_wide_sweep", new_callable=AsyncMock)
def test_wide_sweep_202_happy_path_critical(mock_enqueue: AsyncMock, client_with: Any) -> None:
    """breadth='critical' resolves to the critical subcategory list and returns 202."""
    mock_enqueue.return_value = "wide_sweep:12345"
    # session.execute is hit twice: (1) active-campaign probe, (2) subcategory query
    results = [
        _FakeMappingsResult([]),  # no active campaign
        _FakeMappingsResult(_mappings_for(["a/x", "b/y", "c/z", "d/w"])),
    ]
    client = client_with(results)

    resp = client.post(
        "/api/v1/campaigns/sweep",
        json={
            "breadth": "critical",
            "budget_per_campaign_usd": "1.50",
            "variant_count": 20,
            "stagger_seconds": 10,
        },
    )
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["subcategory_count"] == 4
    assert body["subcategories"] == ["a/x", "b/y", "c/z", "d/w"]
    assert Decimal(body["estimated_total_usd"]) == Decimal("6.00")
    assert body["sweep_job_id"] == "wide_sweep:12345"
    mock_enqueue.assert_awaited_once()


@patch("src.routes.campaigns.enqueue_wide_sweep", new_callable=AsyncMock)
def test_wide_sweep_409_active_campaign(mock_enqueue: AsyncMock, client_with: Any) -> None:
    """Refuses with 409 when a campaign is already pending/in_progress."""
    results = [_FakeMappingsResult([{"?column?": 1}])]
    client = client_with(results)

    resp = client.post(
        "/api/v1/campaigns/sweep",
        json={
            "breadth": "all",
            "budget_per_campaign_usd": "1.00",
        },
    )
    assert resp.status_code == 409
    body = resp.json()
    assert "pending" in body["detail"].lower() or "in_progress" in body["detail"]
    mock_enqueue.assert_not_called()


def test_wide_sweep_422_invalid_breadth(client_with: Any) -> None:
    """Breadth must be one of the three Literal values."""
    client = client_with([])
    resp = client.post(
        "/api/v1/campaigns/sweep",
        json={"breadth": "everything", "budget_per_campaign_usd": "1.00"},
    )
    assert resp.status_code == 422


def test_wide_sweep_422_budget_below_min(client_with: Any) -> None:
    client = client_with([])
    resp = client.post(
        "/api/v1/campaigns/sweep",
        json={"breadth": "critical", "budget_per_campaign_usd": "0.05"},
    )
    assert resp.status_code == 422


def test_wide_sweep_422_budget_above_max(client_with: Any) -> None:
    client = client_with([])
    resp = client.post(
        "/api/v1/campaigns/sweep",
        json={"breadth": "critical", "budget_per_campaign_usd": "50.01"},
    )
    assert resp.status_code == 422


def test_wide_sweep_422_variant_count_above_max(client_with: Any) -> None:
    client = client_with([])
    resp = client.post(
        "/api/v1/campaigns/sweep",
        json={
            "breadth": "critical",
            "budget_per_campaign_usd": "1.00",
            "variant_count": 51,
        },
    )
    assert resp.status_code == 422


@patch("src.routes.campaigns.enqueue_wide_sweep", new_callable=AsyncMock)
def test_wide_sweep_400_no_subcategories(mock_enqueue: AsyncMock, client_with: Any) -> None:
    """When the breadth resolves to zero rows, return 400."""
    results = [
        _FakeMappingsResult([]),  # no active campaign
        _FakeMappingsResult([]),  # no subcategories matched
    ]
    client = client_with(results)
    resp = client.post(
        "/api/v1/campaigns/sweep",
        json={"breadth": "critical", "budget_per_campaign_usd": "1.00"},
    )
    assert resp.status_code == 400
    mock_enqueue.assert_not_called()


# ---------------------------------------------------------------------------
# Breadth resolver direct unit test (filters argument shape)
# ---------------------------------------------------------------------------


def test_breadth_filters_map_to_priorities() -> None:
    """Static map encodes the three buckets correctly."""
    f = campaigns_route._WIDE_SWEEP_PRIORITY_FILTERS
    assert f["critical"] == ("critical",)
    assert f["critical_plus_high"] == ("critical", "high")
    assert f["all"] == ("critical", "high", "medium", "low")


@pytest.mark.asyncio
async def test_resolve_sweep_subcategories_critical_only() -> None:
    """The resolver queries with the priority list and returns subcategories in order."""
    captured: dict[str, Any] = {}

    async def fake_execute(stmt: Any, params: dict[str, Any]) -> _FakeMappingsResult:
        captured["params"] = params
        return _FakeMappingsResult(_mappings_for(["a/x", "b/y"]))

    session = AsyncMock()
    session.execute = fake_execute  # type: ignore[assignment]
    subs = await campaigns_route._resolve_sweep_subcategories(session, "critical")
    assert subs == ["a/x", "b/y"]
    assert captured["params"] == {"priorities": ["critical"]}


@pytest.mark.asyncio
async def test_resolve_sweep_subcategories_critical_plus_high() -> None:
    captured: dict[str, Any] = {}

    async def fake_execute(stmt: Any, params: dict[str, Any]) -> _FakeMappingsResult:
        captured["params"] = params
        return _FakeMappingsResult(_mappings_for(["a", "b", "c"]))

    session = AsyncMock()
    session.execute = fake_execute  # type: ignore[assignment]
    subs = await campaigns_route._resolve_sweep_subcategories(session, "critical_plus_high")
    assert len(subs) == 3
    assert captured["params"] == {"priorities": ["critical", "high"]}


@pytest.mark.asyncio
async def test_resolve_sweep_subcategories_all() -> None:
    captured: dict[str, Any] = {}

    async def fake_execute(stmt: Any, params: dict[str, Any]) -> _FakeMappingsResult:
        captured["params"] = params
        return _FakeMappingsResult(_mappings_for([f"s{i}" for i in range(16)]))

    session = AsyncMock()
    session.execute = fake_execute  # type: ignore[assignment]
    subs = await campaigns_route._resolve_sweep_subcategories(session, "all")
    assert len(subs) == 16
    assert captured["params"] == {"priorities": ["critical", "high", "medium", "low"]}


# ---------------------------------------------------------------------------
# Worker tests
# ---------------------------------------------------------------------------


def _fake_campaign_with_id(target_subcategory: str) -> Campaign:
    return Campaign(
        id=uuid4(),
        status=CampaignStatus.PENDING,
        mode=CampaignMode.LIVE,
        budget_usd=Decimal("1.00"),
        target_version_id=None,
        target_subcategory=target_subcategory,
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        version_id=1,
    )


@pytest.mark.asyncio
@patch("src.workers.wide_sweep_worker.enqueue_orchestrator_tick", new_callable=AsyncMock)
@patch("src.workers.wide_sweep_worker.CampaignRepository")
async def test_run_wide_sweep_creates_campaign_per_subcategory(
    mock_repo_cls: MagicMock, mock_enqueue: AsyncMock
) -> None:
    """Given 3 subcategories, creates 3 campaigns + 3 enqueues, in order."""
    mock_factory = MagicMock()
    fake_session = AsyncMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=fake_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    subs = ["cat/a", "cat/b", "cat/c"]
    created = [_fake_campaign_with_id(s) for s in subs]
    repo_instance = mock_repo_cls.return_value
    repo_instance.create = AsyncMock(side_effect=created)

    ctx = {"session_factory": mock_factory}
    result = await run_wide_sweep(
        ctx,
        subcategories=subs,
        budget_per_campaign_usd="1.50",
        variant_count=10,
        stagger_seconds=0,  # no sleep in tests
        request_id="rid-xyz",
    )

    assert result["subcategory_count"] == 3
    assert len(result["campaign_ids"]) == 3
    # Order preserved
    for call, expected_sub in zip(repo_instance.create.call_args_list, subs, strict=True):
        assert call.kwargs["target_subcategory"] == expected_sub
        assert call.kwargs["budget_usd"] == Decimal("1.50")
    assert mock_enqueue.await_count == 3


@pytest.mark.asyncio
@patch("src.workers.wide_sweep_worker.asyncio.sleep", new_callable=AsyncMock)
@patch("src.workers.wide_sweep_worker.enqueue_orchestrator_tick", new_callable=AsyncMock)
@patch("src.workers.wide_sweep_worker.CampaignRepository")
async def test_run_wide_sweep_sleeps_between_campaigns_not_after_last(
    mock_repo_cls: MagicMock,
    mock_enqueue: AsyncMock,
    mock_sleep: AsyncMock,
) -> None:
    """Stagger sleep fires N-1 times for N subcategories."""
    mock_factory = MagicMock()
    fake_session = AsyncMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=fake_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    subs = ["a", "b", "c", "d"]
    created = [_fake_campaign_with_id(s) for s in subs]
    repo_instance = mock_repo_cls.return_value
    repo_instance.create = AsyncMock(side_effect=created)

    ctx = {"session_factory": mock_factory}
    await run_wide_sweep(
        ctx,
        subcategories=subs,
        budget_per_campaign_usd="2.00",
        variant_count=5,
        stagger_seconds=7,
        request_id="rid",
    )
    # N-1 sleeps for N campaigns
    assert mock_sleep.await_count == 3
    for call in mock_sleep.await_args_list:
        assert call.args[0] == 7
