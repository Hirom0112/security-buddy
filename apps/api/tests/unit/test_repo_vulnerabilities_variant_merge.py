"""Unit tests for the variant-merge repository methods.

Mirrors the SQL-binding style of test_repo_vulnerabilities_append_note.py:
we mock session.execute and assert that the SQL clauses and parameters we
emit match the contract. Full Postgres round-trip lives in tests/integration.
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


def _row_mapping(
    *,
    variant_count: int = 1,
    response_shape_hash: str | None = None,
) -> dict[str, object]:
    return {
        "id": uuid4(),
        "vuln_id": "VUL-0001",
        "attack_id": uuid4(),
        "verdict_id": uuid4(),
        "severity": VulnerabilitySeverity.HIGH.value,
        "title": "t",
        "clinical_impact": "x",
        "reproduction_steps": "x",
        "observed_behavior": "x",
        "expected_behavior": "x",
        "recommended_remediation": "x",
        "status": VulnerabilityStatus.OPEN.value,
        "owasp_llm_id": "LLM02:2025",
        "mitre_atlas_technique_id": "AML.T0051",
        "hipaa_safeguard": "164.312(b)",
        "framework_versions": {"owasp_llm": "2025-v2.0"},
        "target_version_id": None,
        "rubric_snapshot": None,
        "created_at": datetime.now(UTC),
        "version_id": 1,
        "notes": [],
        "response_shape_hash": response_shape_hash,
        "variant_count": variant_count,
        "variant_of_vuln_id": None,
    }


def _stub_session(row: dict[str, object] | None) -> MagicMock:
    result = MagicMock()
    mappings = MagicMock()
    mappings.first = MagicMock(return_value=row)
    result.mappings = MagicMock(return_value=mappings)
    session = MagicMock()
    session.execute = AsyncMock(return_value=result)
    return session


@pytest.mark.asyncio
async def test_find_existing_variant_binds_subcategory_hash_and_target() -> None:
    """find_existing_variant filters by subcategory + hash + target_version_id."""
    repo = VulnerabilityRepository()
    tvid = uuid4()
    session = _stub_session(_row_mapping(response_shape_hash="abc1234567890def"))

    out = await repo.find_existing_variant(
        session,
        subcategory="data_exfiltration/cross_patient_leakage",
        response_shape_hash="abc1234567890def",
        target_version_id=tvid,
    )
    assert isinstance(out, Vulnerability)

    args, _ = session.execute.call_args
    sql = str(args[0])
    params = args[1]
    # Joins to attacks for subcategory
    assert "JOIN attacks" in sql or "join attacks" in sql.lower()
    assert "response_shape_hash" in sql
    assert "draft" in sql and "open" in sql  # status gate
    assert params["h"] == "abc1234567890def"
    assert params["sub"] == "data_exfiltration/cross_patient_leakage"
    assert params["tvid"] == str(tvid)


@pytest.mark.asyncio
async def test_find_existing_variant_returns_none_when_no_match() -> None:
    repo = VulnerabilityRepository()
    session = _stub_session(None)
    out = await repo.find_existing_variant(
        session,
        subcategory="x/y",
        response_shape_hash="0000000000000000",
        target_version_id=None,
    )
    assert out is None


@pytest.mark.asyncio
async def test_find_existing_variant_with_null_target_version_id() -> None:
    """When target_version_id is None we match rows where it's also NULL."""
    repo = VulnerabilityRepository()
    session = _stub_session(_row_mapping())
    await repo.find_existing_variant(
        session,
        subcategory="x/y",
        response_shape_hash="hh",
        target_version_id=None,
    )
    args, _ = session.execute.call_args
    sql = str(args[0])
    params = args[1]
    assert ":tvid IS NULL" in sql or "tvid is null" in sql.lower()
    assert params["tvid"] is None


@pytest.mark.asyncio
async def test_increment_variant_count_bumps_and_appends_note() -> None:
    repo = VulnerabilityRepository()
    vuln_id = uuid4()
    note = {
        "action": "merged_variant",
        "source_attack_id": str(uuid4()),
        "response_shape_hash": "deadbeefcafebabe",
    }
    session = _stub_session(_row_mapping(variant_count=2))

    out = await repo.increment_variant_count(session, vulnerability_id=vuln_id, merge_note=note)
    assert out is not None
    assert out.variant_count == 2

    args, _ = session.execute.call_args
    sql = str(args[0])
    params = args[1]
    assert "variant_count = variant_count + 1" in sql
    assert "notes = notes ||" in sql
    assert "version_id = version_id + 1" in sql
    assert params["id"] == str(vuln_id)
    assert json.loads(params["note"]) == note


@pytest.mark.asyncio
async def test_increment_variant_count_returns_none_when_missing() -> None:
    repo = VulnerabilityRepository()
    session = _stub_session(None)
    out = await repo.increment_variant_count(
        session,
        vulnerability_id=uuid4(),
        merge_note={"action": "merged_variant"},
    )
    assert out is None


@pytest.mark.asyncio
async def test_create_passes_response_shape_hash() -> None:
    """create() must bind response_shape_hash to the INSERT params."""
    repo = VulnerabilityRepository()

    # We need 3 sequential session.execute calls:
    #   1) get_by_attack_id (returns None — no existing)
    #   2) pg_advisory_xact_lock (returns nothing meaningful)
    #   3) SELECT COUNT(*) — returns {'c': 0}
    #   4) INSERT … RETURNING — returns the new row
    inserted_row = _row_mapping(response_shape_hash="cafebabedeadbeef")
    call_results: list[MagicMock] = []

    def _make_result(row: dict[str, object] | None) -> MagicMock:
        r = MagicMock()
        m = MagicMock()
        m.first = MagicMock(return_value=row)
        r.mappings = MagicMock(return_value=m)
        return r

    call_results.append(_make_result(None))  # get_by_attack_id
    call_results.append(_make_result(None))  # pg_advisory_xact_lock
    call_results.append(_make_result({"c": 0}))  # SELECT COUNT
    call_results.append(_make_result(inserted_row))  # INSERT RETURNING

    session = MagicMock()
    session.execute = AsyncMock(side_effect=call_results)

    out = await repo.create(
        session,
        attack_id=uuid4(),
        verdict_id=uuid4(),
        severity="high",
        title="t",
        clinical_impact="i",
        reproduction_steps="r",
        observed_behavior="o",
        expected_behavior="e",
        recommended_remediation="rr",
        status="open",
        owasp_llm_id="LLM02:2025",
        mitre_atlas_technique_id="AML.T0051",
        hipaa_safeguard="164.312(b)",
        framework_versions={"owasp_llm": "2025-v2.0"},
        target_version_id=None,
        rubric_snapshot=None,
        response_shape_hash="cafebabedeadbeef",
    )
    assert isinstance(out, Vulnerability)
    assert out.response_shape_hash == "cafebabedeadbeef"

    # 4th call is the INSERT; assert the shape_hash is bound.
    insert_call = session.execute.await_args_list[3]
    args, _ = insert_call
    sql = str(args[0])
    params = args[1]
    assert "response_shape_hash" in sql
    assert params["response_shape_hash"] == "cafebabedeadbeef"
