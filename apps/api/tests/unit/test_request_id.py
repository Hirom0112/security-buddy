"""Unit tests for the request_id ContextVar propagation."""

import asyncio

import pytest

from src.observability.context import get_request_id, set_request_id


class TestRequestIdContextVar:
    @pytest.mark.asyncio
    async def test_default_is_none(self) -> None:
        # In pytest-asyncio's auto mode, each test gets its own event loop context.
        # ContextVar default should be None at the start of a fresh coroutine.
        assert get_request_id() is None

    @pytest.mark.asyncio
    async def test_set_and_get(self) -> None:
        set_request_id("test-request-id-123")
        assert get_request_id() == "test-request-id-123"

    @pytest.mark.asyncio
    async def test_isolation_between_tasks(self) -> None:
        """Two concurrent tasks must not share request_id values."""

        async def task_a() -> str | None:
            set_request_id("request-a")
            await asyncio.sleep(0)  # yield to allow task_b to run
            return get_request_id()

        async def task_b() -> str | None:
            set_request_id("request-b")
            await asyncio.sleep(0)
            return get_request_id()

        a, b = await asyncio.gather(task_a(), task_b())
        # Each task sees its own value
        assert a == "request-a"
        assert b == "request-b"

    @pytest.mark.asyncio
    async def test_overwrite(self) -> None:
        set_request_id("first")
        assert get_request_id() == "first"
        set_request_id("second")
        assert get_request_id() == "second"
