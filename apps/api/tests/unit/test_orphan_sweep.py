"""Startup orphan-pending sweep — flips stuck campaigns to 'halted'.

A campaign sitting in 'pending' for more than _ORPHAN_PENDING_THRESHOLD_MINUTES
on app boot is an orphan (worker crashed mid-pickup or enqueue failed) and
must not pollute the dashboard. The sweep runs in the FastAPI lifespan and
is idempotent — repeated boots are safe.
"""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# Mirror the other test files: pre-fill env before importing src.
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
    "TARGET_COPILOT_MODULE_PATH",
    "/interface/modules/custom_modules/copilot/index.php",
)
os.environ.setdefault("TARGET_LOGIN_USER", "sara")
os.environ.setdefault("TARGET_LOGIN_PASSWORD", "chen")

from src.main import _sweep_orphan_pending_campaigns


def _build_factory(swept_rows: list[tuple[Any]]) -> Any:
    """Return a session_factory-shaped mock that yields a session whose
    execute() returns a result whose fetchall() gives `swept_rows`."""
    session = AsyncMock()
    result = MagicMock()
    result.fetchall.return_value = swept_rows
    session.execute = AsyncMock(return_value=result)
    session.commit = AsyncMock(return_value=None)
    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=session)
    factory.return_value.__aexit__ = AsyncMock(return_value=None)
    return factory, session


@pytest.mark.asyncio
async def test_sweep_no_orphans_is_noop() -> None:
    factory, session = _build_factory([])
    await _sweep_orphan_pending_campaigns(factory)
    # Single UPDATE issued, commit called, no exception.
    assert session.execute.await_count == 1
    session.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_sweep_flips_orphans() -> None:
    factory, session = _build_factory(
        [("11111111-1111-1111-1111-111111111111",), ("22222222-2222-2222-2222-222222222222",)]
    )
    await _sweep_orphan_pending_campaigns(factory)
    # The UPDATE is the only statement; commit follows it.
    assert session.execute.await_count == 1
    session.commit.assert_awaited_once()
    # The SQL targets the right status and uses an interval threshold.
    args, _kwargs = session.execute.await_args
    sql = str(args[0])
    assert "pending" in sql
    assert "halted" in sql
    assert "interval" in sql.lower()
