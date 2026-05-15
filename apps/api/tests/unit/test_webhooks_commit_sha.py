"""Slice 6 DoD #3: webhook captures merge_commit_sha for offending-commit attribution.

When the GitHub merge webhook fires with a pull_request payload that
contains a merge_commit_sha, the webhook forwards that SHA to the
regression-sweep enqueue as the commit_sha argument so the worker can
stamp it on the new target_versions row.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

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
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-webhook-secret")

from src.main import app
from src.settings import get_settings


@pytest.fixture
def client() -> TestClient:
    mock_factory = MagicMock()
    fake_session = AsyncMock()
    default_result = MagicMock()
    default_result.mappings.return_value.first.return_value = None
    default_result.scalar.return_value = 1
    fake_session.execute = AsyncMock(return_value=default_result)
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=fake_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)
    app.state.session_factory = mock_factory

    if not hasattr(app.state, "limiter"):
        from slowapi import Limiter
        from slowapi.util import get_remote_address

        app.state.limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

    get_settings.cache_clear()
    return TestClient(app, raise_server_exceptions=False)


def _sign(body_bytes: bytes, secret: str = "test-webhook-secret") -> str:
    digest = hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


@patch(
    "src.routes.webhooks.enqueue_harness_regression_sweep",
    new_callable=AsyncMock,
)
@patch("src.routes.webhooks.PatchRepository")
def test_webhook_forwards_merge_commit_sha_to_enqueue(
    mock_repo_cls: Any,
    mock_enqueue: AsyncMock,
    client: TestClient,
) -> None:
    """The merge_commit_sha from the webhook payload is forwarded as commit_sha."""
    mock_repo = MagicMock()
    mock_repo.get_by_branch_name = AsyncMock(return_value=None)
    mock_repo_cls.return_value = mock_repo

    sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    body = json.dumps(
        {
            "action": "closed",
            "pull_request": {
                "number": 7,
                "merged": True,
                "merge_commit_sha": sha,
                "base": {"ref": "main"},
                "head": {"ref": "security-buddy/vul-0007"},
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
    mock_enqueue.assert_awaited_once()
    kwargs = mock_enqueue.await_args.kwargs
    assert kwargs.get("commit_sha") == sha
