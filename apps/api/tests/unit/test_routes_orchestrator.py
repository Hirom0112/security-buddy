"""Unit tests for POST /api/v1/campaigns/start and POST /webhooks/github.

Builds on the same env-setup + TestClient pattern as test_routes_campaigns.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from decimal import Decimal
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

# Mirror the env setup in test_routes_campaigns.py — keep in sync.
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
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-webhook-secret")

from src.domain.campaign import Campaign, CampaignStatus
from src.main import app
from src.settings import get_settings

_CAMPAIGN_ID = uuid4()


def _fake_campaign() -> Campaign:
    return Campaign(
        id=_CAMPAIGN_ID,
        status=CampaignStatus.PENDING,
        budget_usd=Decimal("5.00"),
        target_version_id=None,
        target_subcategory=None,
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        version_id=1,
    )


@pytest.fixture
def client() -> TestClient:
    mock_factory = MagicMock()
    fake_session = AsyncMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=fake_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    app.state.session_factory = mock_factory
    if not hasattr(app.state, "limiter"):
        from slowapi import Limiter
        from slowapi.util import get_remote_address

        app.state.limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

    # Reset settings cache so the GITHUB_WEBHOOK_SECRET env we set above is picked up.
    get_settings.cache_clear()

    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# /api/v1/campaigns/start
# ---------------------------------------------------------------------------


@patch("src.routes.campaigns.enqueue_orchestrator_tick", new_callable=AsyncMock)
@patch("src.routes.campaigns.CampaignRepository")
def test_start_campaign_enqueues_orchestrator_tick(
    mock_repo_cls: Any,
    mock_enqueue: AsyncMock,
    client: TestClient,
) -> None:
    repo = MagicMock()
    repo.create = AsyncMock(return_value=_fake_campaign())
    mock_repo_cls.return_value = repo

    resp = client.post("/api/v1/campaigns/start", json={"budget_usd": "5.00"})

    assert resp.status_code == 202
    body = resp.json()
    assert body["campaign_id"] == str(_CAMPAIGN_ID)
    assert body["status"] == "pending"

    # Created with target_subcategory=None — that's the empty-start contract.
    args, kwargs = repo.create.call_args
    assert kwargs["target_subcategory"] is None

    mock_enqueue.assert_awaited_once()


def test_start_campaign_422_missing_budget(client: TestClient) -> None:
    resp = client.post("/api/v1/campaigns/start", json={})
    assert resp.status_code == 422


def test_start_campaign_422_budget_too_large(client: TestClient) -> None:
    resp = client.post("/api/v1/campaigns/start", json={"budget_usd": "200.00"})
    assert resp.status_code == 422


def test_start_campaign_422_negative_budget(client: TestClient) -> None:
    resp = client.post("/api/v1/campaigns/start", json={"budget_usd": "-1.00"})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /webhooks/github
# ---------------------------------------------------------------------------


def _sign(body_bytes: bytes, secret: str = "test-webhook-secret") -> str:
    digest = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_github_webhook_ping_acknowledged(client: TestClient) -> None:
    body = json.dumps({"zen": "Speak like a human."}).encode()
    resp = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "pong"


def test_github_webhook_merged_pr_accepted(client: TestClient) -> None:
    body = json.dumps(
        {
            "action": "closed",
            "pull_request": {
                "number": 42,
                "merged": True,
                "merge_commit_sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "base": {"ref": "main"},
            },
        }
    ).encode()
    resp = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    payload = resp.json()
    assert payload["status"] == "accepted"
    assert payload["pr_number"] == 42


def test_github_webhook_unmerged_pr_ignored(client: TestClient) -> None:
    body = json.dumps(
        {
            "action": "closed",
            "pull_request": {"number": 1, "merged": False, "base": {"ref": "main"}},
        }
    ).encode()
    resp = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "ignored"


def test_github_webhook_wrong_signature_rejected(client: TestClient) -> None:
    body = json.dumps({"foo": "bar"}).encode()
    resp = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 401


def test_github_webhook_missing_signature_rejected(client: TestClient) -> None:
    body = json.dumps({"foo": "bar"}).encode()
    resp = client.post(
        "/webhooks/github",
        content=body,
        headers={"X-GitHub-Event": "ping", "Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_github_webhook_secret_unset_returns_503(client: TestClient) -> None:
    """Fail-closed: no secret configured → no acceptance."""
    # Drop the env var, clear cache so settings re-read.
    original = os.environ.pop("GITHUB_WEBHOOK_SECRET", None)
    try:
        get_settings.cache_clear()
        body = json.dumps({"foo": "bar"}).encode()
        resp = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "X-GitHub-Event": "ping",
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 503
    finally:
        if original is not None:
            os.environ["GITHUB_WEBHOOK_SECRET"] = original
        get_settings.cache_clear()


def test_github_webhook_non_pr_event_ignored(client: TestClient) -> None:
    body = json.dumps({"action": "opened"}).encode()
    resp = client.post(
        "/webhooks/github",
        content=body,
        headers={
            "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": _sign(body),
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 202
    assert resp.json()["status"] == "ignored"
