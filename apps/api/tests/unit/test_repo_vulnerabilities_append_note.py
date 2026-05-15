"""Unit test for VulnerabilityRepository.append_note().

Verifies the SQL params we send to Postgres: id, jsonb-serialised note,
and the optimistic-lock version constraint when present. The full
end-to-end Postgres round-trip lives in tests/integration.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.domain.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from src.repositories.vulnerabilities import VulnerabilityRepository


def _row_mapping() -> dict[str, object]:
    return {
        "id": uuid4(),
        "vuln_id": "VUL-0001",
        "attack_id": uuid4(),
        "verdict_id": uuid4(),
        "severity": VulnerabilitySeverity.CRITICAL.value,
        "title": "t",
        "clinical_impact": "x",
        "reproduction_steps": "x",
        "observed_behavior": "x",
        "expected_behavior": "x",
        "recommended_remediation": "x",
        "status": VulnerabilityStatus.DRAFT.value,
        "owasp_llm_id": "LLM01:2025",
        "mitre_atlas_technique_id": "AML.T0051",
        "hipaa_safeguard": "164.312(b)",
        "framework_versions": {"owasp_llm": "2025-v2.0"},
        "target_version_id": None,
        "rubric_snapshot": None,
        "created_at": datetime.now(UTC),
        "version_id": 2,
        "notes": [{"action": "dismiss", "reason": "stale"}],
    }


def _stub_session(row: dict[str, object] | None) -> tuple[MagicMock, MagicMock]:
    """Build a session.execute mock that returns `row` via mappings().first()."""
    result = MagicMock()
    mappings = MagicMock()
    mappings.first = MagicMock(return_value=row)
    result.mappings = MagicMock(return_value=mappings)

    session = MagicMock()
    session.execute = AsyncMock(return_value=result)
    return session, result


@pytest.mark.asyncio
async def test_append_note_binds_id_and_note_json() -> None:
    """Without expected_version_id the SQL only filters on id."""
    repo = VulnerabilityRepository()
    vuln_id = uuid4()
    note = {"at": "2026-05-15T00:00:00+00:00", "actor": "operator", "reason": "fp"}

    session, _ = _stub_session(_row_mapping())

    out = await repo.append_note(session, vulnerability_id=vuln_id, note=note)

    assert isinstance(out, Vulnerability)
    assert out.notes[0]["action"] == "dismiss"

    session.execute.assert_called_once()
    args, _ = session.execute.call_args
    sql_clause = str(args[0])
    params = args[1]
    assert "notes = notes ||" in sql_clause
    assert "version_id = version_id + 1" in sql_clause
    assert "version_id = :v" not in sql_clause  # no optimistic constraint
    assert params["id"] == str(vuln_id)
    assert json.loads(params["note"]) == note


@pytest.mark.asyncio
async def test_append_note_with_optimistic_version() -> None:
    """When expected_version_id is set, the WHERE adds version_id = :v."""
    repo = VulnerabilityRepository()
    vuln_id = uuid4()
    note = {"action": "dismiss", "reason": "ok"}

    session, _ = _stub_session(_row_mapping())

    out = await repo.append_note(
        session,
        vulnerability_id=vuln_id,
        note=note,
        expected_version_id=7,
    )
    assert out is not None

    args, _ = session.execute.call_args
    sql_clause = str(args[0])
    params = args[1]
    assert "version_id = :v" in sql_clause
    assert params["v"] == 7


@pytest.mark.asyncio
async def test_append_note_returns_none_when_no_row() -> None:
    """If the UPDATE matches no row (concurrent update), return None."""
    repo = VulnerabilityRepository()
    session, _ = _stub_session(None)

    out = await repo.append_note(
        session,
        vulnerability_id=uuid4(),
        note={"action": "dismiss", "reason": "x"},
        expected_version_id=1,
    )
    assert out is None
