"""Unit tests for POST /api/v1/campaigns.

Mocks:
  - CampaignRepository (DB writes)
  - _subcategory_exists (taxonomy lookup)
  - enqueue_red_team_execute (arq queue)
  - app.state.session_factory (no real DB)

All tests are synchronous from pytest's perspective but use asyncio under
the hood via pytest-asyncio (asyncio_mode = "auto").
"""

from __future__ import annotations

import os
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Environment setup — must happen before importing src modules that call
# get_settings() at module load time.
#
# IMPORTANT: these values are scoped to be SAFE to leak across test files —
# DATABASE_URL points at the same dockerised local Postgres that integration
# tests use, so if pytest imports this module first and other tests inherit
# the env, they still connect to the right DB. Using a "x:x" placeholder
# here previously broke the integration suite (incident: 2026-05-12).
# ---------------------------------------------------------------------------

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

from src.domain.campaign import BriefStatus, Campaign, CampaignBrief, CampaignStatus
from src.main import app

# ---------------------------------------------------------------------------
# Fake domain objects returned by mocked repositories.
# ---------------------------------------------------------------------------

_FAKE_CAMPAIGN_ID = uuid4()
_FAKE_BRIEF_ID = uuid4()


def _fake_campaign() -> Campaign:
    from datetime import UTC, datetime

    return Campaign(
        id=_FAKE_CAMPAIGN_ID,
        status=CampaignStatus.PENDING,
        budget_usd=Decimal("5.00"),
        target_version_id=None,
        target_subcategory="prompt_injection/indirect_via_upload",
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        version_id=1,
    )


def _fake_brief() -> CampaignBrief:
    from datetime import UTC, datetime

    return CampaignBrief(
        id=_FAKE_BRIEF_ID,
        campaign_id=_FAKE_CAMPAIGN_ID,
        target_subcategory="prompt_injection/indirect_via_upload",
        description="Test the indirect prompt-injection surface",
        variant_count=5,
        success_criteria={},
        budget_usd=Decimal("5.00"),
        status=BriefStatus.PENDING,
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client() -> TestClient:
    """Return a synchronous TestClient with a fake session_factory on app.state."""
    mock_factory = MagicMock()
    # The factory is used as an async context manager in the route.
    fake_session = AsyncMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=fake_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    app.state.session_factory = mock_factory
    # Ensure limiter state is set (populated in lifespan, not called during tests)
    if not hasattr(app.state, "limiter"):
        from slowapi import Limiter
        from slowapi.util import get_remote_address

        app.state.limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

    return TestClient(app, raise_server_exceptions=False)


def _valid_body(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "target_subcategory": "prompt_injection/indirect_via_upload",
        "description": "End-to-end indirect prompt injection test",
        "variant_count": 5,
        "budget_usd": "5.00",
        "success_criteria": {},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@patch("src.routes.campaigns.enqueue_red_team_execute", new_callable=AsyncMock)
@patch("src.routes.campaigns._subcategory_exists", new_callable=AsyncMock)
@patch("src.routes.campaigns.CampaignRepository")
def test_create_campaign_202(
    mock_repo_cls: MagicMock,
    mock_subcategory_exists: AsyncMock,
    mock_enqueue: AsyncMock,
    client: TestClient,
) -> None:
    """Valid request returns 202 with campaign_id, brief_id, and status=pending."""
    mock_subcategory_exists.return_value = True
    repo_instance = mock_repo_cls.return_value
    repo_instance.create = AsyncMock(return_value=_fake_campaign())
    repo_instance.add_brief = AsyncMock(return_value=_fake_brief())

    resp = client.post("/api/v1/campaigns", json=_valid_body())

    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["campaign_id"] == str(_FAKE_CAMPAIGN_ID)
    assert data["brief_id"] == str(_FAKE_BRIEF_ID)
    assert data["status"] == "pending"
    assert "enqueued_at" in data

    mock_enqueue.assert_called_once()
    call_kwargs = mock_enqueue.call_args
    # First positional arg is brief_id
    assert call_kwargs[0][0] == _FAKE_BRIEF_ID


@patch("src.routes.campaigns.enqueue_red_team_execute", new_callable=AsyncMock)
@patch("src.routes.campaigns._subcategory_exists", new_callable=AsyncMock)
@patch("src.routes.campaigns.CampaignRepository")
def test_create_campaign_400_unknown_subcategory(
    mock_repo_cls: MagicMock,
    mock_subcategory_exists: AsyncMock,
    mock_enqueue: AsyncMock,
    client: TestClient,
) -> None:
    """Unknown target_subcategory returns 400 RFC 7807 problem detail."""
    mock_subcategory_exists.return_value = False

    resp = client.post(
        "/api/v1/campaigns",
        json=_valid_body(target_subcategory="nonexistent/subcategory"),
    )

    assert resp.status_code == 400
    body = resp.json()
    assert body["status"] == 400
    assert "subcategory" in body["detail"].lower() or "nonexistent" in body["detail"]
    mock_enqueue.assert_not_called()


def test_create_campaign_422_missing_fields(client: TestClient) -> None:
    """Missing required fields return 422."""
    resp = client.post(
        "/api/v1/campaigns",
        json={"target_subcategory": "pi/x"},  # missing description, variant_count, budget_usd
    )
    assert resp.status_code == 422


def test_create_campaign_422_variant_count_out_of_range(client: TestClient) -> None:
    """variant_count=0 fails validation."""
    resp = client.post(
        "/api/v1/campaigns",
        json=_valid_body(variant_count=0),
    )
    assert resp.status_code == 422


def test_create_campaign_422_budget_too_large(client: TestClient) -> None:
    """budget_usd > 100 fails validation."""
    resp = client.post(
        "/api/v1/campaigns",
        json=_valid_body(budget_usd="101.00"),
    )
    assert resp.status_code == 422


def test_create_campaign_422_description_too_short(client: TestClient) -> None:
    """description shorter than 10 chars fails validation."""
    resp = client.post(
        "/api/v1/campaigns",
        json=_valid_body(description="short"),
    )
    assert resp.status_code == 422


@patch("src.routes.campaigns.enqueue_red_team_execute", new_callable=AsyncMock)
@patch("src.routes.campaigns._subcategory_exists", new_callable=AsyncMock)
@patch("src.routes.campaigns.CampaignRepository")
def test_request_id_propagates_into_enqueue(
    mock_repo_cls: MagicMock,
    mock_subcategory_exists: AsyncMock,
    mock_enqueue: AsyncMock,
    client: TestClient,
) -> None:
    """X-Request-Id header propagates into the enqueue call's request_id argument."""
    mock_subcategory_exists.return_value = True
    repo_instance = mock_repo_cls.return_value
    repo_instance.create = AsyncMock(return_value=_fake_campaign())
    repo_instance.add_brief = AsyncMock(return_value=_fake_brief())

    test_request_id = "test-rid-abc123"
    resp = client.post(
        "/api/v1/campaigns",
        json=_valid_body(),
        headers={"X-Request-Id": test_request_id},
    )

    assert resp.status_code == 202, resp.text

    mock_enqueue.assert_called_once()
    call_args = mock_enqueue.call_args[0]
    # Second positional arg is request_id
    propagated_rid: str = call_args[1]
    assert propagated_rid == test_request_id


@patch("src.routes.campaigns.enqueue_red_team_execute", new_callable=AsyncMock)
@patch("src.routes.campaigns._subcategory_exists", new_callable=AsyncMock)
@patch("src.routes.campaigns.CampaignRepository")
def test_enqueue_called_once_per_request(
    mock_repo_cls: MagicMock,
    mock_subcategory_exists: AsyncMock,
    mock_enqueue: AsyncMock,
    client: TestClient,
) -> None:
    """enqueue_red_team_execute is called exactly once per valid POST."""
    mock_subcategory_exists.return_value = True
    repo_instance = mock_repo_cls.return_value
    repo_instance.create = AsyncMock(return_value=_fake_campaign())
    repo_instance.add_brief = AsyncMock(return_value=_fake_brief())

    client.post("/api/v1/campaigns", json=_valid_body())
    assert mock_enqueue.call_count == 1
