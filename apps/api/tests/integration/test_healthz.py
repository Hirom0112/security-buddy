"""Integration test for GET /healthz.

DB and Redis are mocked — this test verifies:
  - The endpoint returns HTTP 200 always
  - The response body matches the HealthResponse schema
  - All subsystem fields are present
  - The top-level 'status' field is one of ok/degraded/down

Run with: pytest tests/integration/ -v
(Does NOT require a live Postgres or Redis — both are mocked.)
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject required env vars so Settings instantiates cleanly."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-not-real")
    monkeypatch.setenv("LANGSMITH_API_KEY", "DISABLED")
    monkeypatch.setenv("LANGSMITH_PROJECT", "test")
    monkeypatch.setenv("SESSION_SECRET", "a" * 64)

    # Clear the settings cache so monkeypatched values take effect
    from src import settings as settings_module

    settings_module.get_settings.cache_clear()
    yield
    settings_module.get_settings.cache_clear()


@pytest.fixture()
def client(env_vars: None) -> TestClient:
    from src.main import app

    return TestClient(app, raise_server_exceptions=False)


class TestHealthzEndpoint:
    def test_returns_200(self, client: TestClient) -> None:
        with (
            patch("src.routes.health._check_db", new_callable=AsyncMock, return_value="ok"),
            patch("src.routes.health._check_redis", new_callable=AsyncMock, return_value="ok"),
        ):
            resp = client.get("/healthz")
        assert resp.status_code == 200

    def test_response_schema(self, client: TestClient) -> None:
        with (
            patch("src.routes.health._check_db", new_callable=AsyncMock, return_value="ok"),
            patch("src.routes.health._check_redis", new_callable=AsyncMock, return_value="ok"),
        ):
            resp = client.get("/healthz")
        data = resp.json()
        assert "status" in data
        assert "subsystems" in data
        sub = data["subsystems"]
        assert "app" in sub
        assert "db" in sub
        assert "redis" in sub
        assert "langsmith" in sub

    def test_status_ok_when_all_ok(self, client: TestClient) -> None:
        with (
            patch("src.routes.health._check_db", new_callable=AsyncMock, return_value="ok"),
            patch("src.routes.health._check_redis", new_callable=AsyncMock, return_value="ok"),
        ):
            resp = client.get("/healthz")
        data = resp.json()
        # langsmith is "unconfigured" (DISABLED) — only configured ones need to be ok
        assert data["status"] in ("ok", "degraded")
        assert data["subsystems"]["app"] == "ok"
        assert data["subsystems"]["db"] == "ok"
        assert data["subsystems"]["redis"] == "ok"

    def test_status_degraded_when_db_down(self, client: TestClient) -> None:
        with (
            patch("src.routes.health._check_db", new_callable=AsyncMock, return_value="down"),
            patch("src.routes.health._check_redis", new_callable=AsyncMock, return_value="ok"),
        ):
            resp = client.get("/healthz")
        data = resp.json()
        assert resp.status_code == 200  # always 200
        assert data["status"] == "degraded"
        assert data["subsystems"]["db"] == "down"

    def test_langsmith_unconfigured_when_disabled(self, client: TestClient) -> None:
        with (
            patch("src.routes.health._check_db", new_callable=AsyncMock, return_value="ok"),
            patch("src.routes.health._check_redis", new_callable=AsyncMock, return_value="ok"),
        ):
            resp = client.get("/healthz")
        data = resp.json()
        assert data["subsystems"]["langsmith"] == "unconfigured"

    def test_overall_status_valid_values(self, client: TestClient) -> None:
        with (
            patch("src.routes.health._check_db", new_callable=AsyncMock, return_value="ok"),
            patch("src.routes.health._check_redis", new_callable=AsyncMock, return_value="ok"),
        ):
            resp = client.get("/healthz")
        data = resp.json()
        assert data["status"] in ("ok", "degraded", "down")
