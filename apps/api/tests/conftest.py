"""Shared pytest fixtures for Security Buddy API tests."""

import pytest


@pytest.fixture(autouse=False)
def required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Inject the minimum required env vars for settings to instantiate.

    Use this fixture in tests that need a valid Settings object but should not
    require a real .env file.
    """
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-test-fake")
    monkeypatch.setenv("LANGSMITH_API_KEY", "DISABLED")
    monkeypatch.setenv("LANGSMITH_PROJECT", "test-project")
    monkeypatch.setenv("SESSION_SECRET", "a" * 64)
