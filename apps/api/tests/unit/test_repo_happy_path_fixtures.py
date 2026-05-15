"""Unit tests for HappyPathFixtureRepository.

Mocks the SQLAlchemy session; verifies that:
  - list_for_manifest() issues the right SQL and parses rows.
  - get_enabled() is the enabled_only=True wrapper.

Full Postgres round-trip lives in tests/integration.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.repositories.happy_path_fixtures import HappyPathFixtureRepository


def _row_mapping() -> dict[str, object]:
    return {
        "id": uuid4(),
        "target_manifest_id": uuid4(),
        "capability_name": "chatbox_patient_census",
        "attack_input": "List the patients on my panel today.",
        "expected_response_shape": {"required_substrings": ["panel", "pt-"]},
        "enabled": True,
        "created_at": datetime.now(UTC),
        "version_id": 1,
    }


@pytest.mark.asyncio
async def test_list_for_manifest_returns_parsed_fixtures() -> None:
    session = AsyncMock()
    result = MagicMock()
    result.mappings.return_value.all.return_value = [_row_mapping()]
    session.execute = AsyncMock(return_value=result)

    repo = HappyPathFixtureRepository()
    rows = await repo.list_for_manifest(session, uuid4())

    assert len(rows) == 1
    assert rows[0].capability_name == "chatbox_patient_census"
    assert rows[0].required_substrings() == ["panel", "pt-"]


@pytest.mark.asyncio
async def test_list_for_manifest_enabled_only_filters_in_sql() -> None:
    """enabled_only=True must include the `enabled = true` predicate."""
    session = AsyncMock()
    result = MagicMock()
    result.mappings.return_value.all.return_value = []
    session.execute = AsyncMock(return_value=result)

    repo = HappyPathFixtureRepository()
    await repo.list_for_manifest(session, uuid4(), enabled_only=True)

    sent_sql = str(session.execute.await_args.args[0])
    assert "enabled = true" in sent_sql


@pytest.mark.asyncio
async def test_get_enabled_delegates_to_list_for_manifest() -> None:
    """get_enabled() must pass enabled_only=True."""
    session = AsyncMock()
    result = MagicMock()
    result.mappings.return_value.all.return_value = [_row_mapping()]
    session.execute = AsyncMock(return_value=result)

    repo = HappyPathFixtureRepository()
    rows = await repo.get_enabled(session, uuid4())

    sent_sql = str(session.execute.await_args.args[0])
    assert "enabled = true" in sent_sql
    assert len(rows) == 1
