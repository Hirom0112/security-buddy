"""Integration test for CoverageRepository.snapshot().

Slice 3 DoD requires: "Coverage query results match a hand-computed expected
output for a seeded test database."

This test seeds 3 attack_taxonomy subcategories with deterministic attack /
verdict / vulnerability rows, calls CoverageRepository.snapshot(), and asserts
each computed field row-by-row against hand-computed expected values.

Fixture (under one fresh target_version_id):
  - Subcat A (prompt_injection/direct, high):
      10 attacks (all judged), 7 exploit verdicts + 3 safe verdicts,
      1 vulnerability with status='open'.
      Expected: attempts=10, exploit_count=7, success_rate=0.7,
                open_findings_count=1, days_since_last_attempted=0.
  - Subcat B (data_exfiltration/phi_in_errors, medium):
      5 attacks, all status='awaiting_judgment' (no verdicts), no vulns.
      Expected: attempts=5, exploit_count=0, success_rate=0.0,
                open_findings_count=0, days_since_last_attempted=0.
  - Subcat C (tool_misuse/recursive_calls, medium):
      0 attacks, no vulns.
      Expected: attempts=0, exploit_count=0, success_rate=0.0,
                open_findings_count=0, days_since_last_attempted=None.

Requires a live Postgres at `alembic upgrade head`. The session fixture rolls
back via savepoints so the test leaves the DB clean.

Run:
    pytest tests/integration/test_coverage_repository.py -v
"""

from __future__ import annotations

import os
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

from src.domain.coverage import TaxonomyPriority
from src.repositories.coverage import CoverageRepository

pytestmark = pytest.mark.integration


SUBCAT_A = "prompt_injection/direct"
SUBCAT_B = "data_exfiltration/phi_in_errors"
SUBCAT_C = "tool_misuse/recursive_calls"


def _db_url() -> str:
    return os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://security_buddy:security_buddy@localhost:5432/security_buddy",
    )


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """Yield a transaction-wrapped session that rolls back after the test."""
    engine = create_async_engine(_db_url(), echo=False)
    async with engine.connect() as conn:
        await conn.begin()
        nested = await conn.begin_nested()
        async_session = AsyncSession(bind=conn, expire_on_commit=False)  # type: ignore[call-arg]
        try:
            yield async_session
        finally:
            await async_session.close()
            await nested.rollback()
    await engine.dispose()


async def _seed_target_version(session: AsyncSession) -> UUID:
    """Create a target_manifest + target_version unique to this test."""
    manifest_id = uuid4()
    target_id = f"test-target-{manifest_id.hex[:8]}"
    await session.execute(
        sa.text(
            "INSERT INTO target_manifests (id, target_id, manifest_json, version)"
            " VALUES (:id, :tid, '{}'::jsonb, '1.0.0')"
        ),
        {"id": str(manifest_id), "tid": target_id},
    )
    version_id = uuid4()
    await session.execute(
        sa.text(
            "INSERT INTO target_versions"
            " (id, target_manifest_id, target_id, version, deployed_at, triggered_by)"
            " VALUES (:id, :mid, :tid, '1.0.0', now(), 'test')"
        ),
        {"id": str(version_id), "mid": str(manifest_id), "tid": target_id},
    )
    return version_id


async def _seed_campaign_and_brief(
    session: AsyncSession,
    *,
    target_version_id: UUID,
    subcategory: str,
) -> tuple[UUID, UUID]:
    """Insert one campaign + one brief scoped to a subcategory under the given target version."""
    campaign_id = uuid4()
    await session.execute(
        sa.text(
            "INSERT INTO campaigns"
            " (id, status, mode, budget_usd, target_version_id,"
            "  target_subcategory, created_at, version_id)"
            " VALUES (:id, 'pending', 'live', :budget, :vid, :sub, now(), 1)"
        ),
        {
            "id": str(campaign_id),
            "budget": str(Decimal("10.00")),
            "vid": str(target_version_id),
            "sub": subcategory,
        },
    )
    brief_id = uuid4()
    await session.execute(
        sa.text(
            "INSERT INTO campaign_briefs"
            " (id, campaign_id, target_subcategory, description, variant_count,"
            "  success_criteria, budget_usd, status, created_at)"
            " VALUES (:id, :cid, :sub, 'coverage test brief', 10,"
            "         '{}'::jsonb, :budget, 'in_progress', now())"
        ),
        {
            "id": str(brief_id),
            "cid": str(campaign_id),
            "sub": subcategory,
            "budget": str(Decimal("10.00")),
        },
    )
    return campaign_id, brief_id


async def _insert_attack(
    session: AsyncSession,
    *,
    campaign_id: UUID,
    brief_id: UUID,
    subcategory: str,
    category: str,
    status: str,
    executed: bool,
) -> UUID:
    attack_id = uuid4()
    await session.execute(
        sa.text(
            "INSERT INTO attacks"
            " (id, campaign_id, brief_id, category, subcategory, mutation_strategy,"
            "  seed_used, attack_input, attack_metadata, target_response,"
            "  target_response_status, target_response_time_ms, status,"
            "  created_at, executed_at)"
            " VALUES (:id, :cid, :bid, :cat, :sub, 'lexical', 'seed-test',"
            "         'payload', '{}'::jsonb, 'response', 200, 100, :status,"
            "         now(), CASE WHEN :exec THEN now() ELSE NULL END)"
        ),
        {
            "id": str(attack_id),
            "cid": str(campaign_id),
            "bid": str(brief_id),
            "cat": category,
            "sub": subcategory,
            "status": status,
            "exec": executed,
        },
    )
    return attack_id


async def _insert_verdict(
    session: AsyncSession,
    *,
    attack_id: UUID,
    verdict: str,
) -> UUID:
    verdict_id = uuid4()
    await session.execute(
        sa.text(
            "INSERT INTO verdicts"
            " (id, attack_id, verdict, confidence, evidence, notes,"
            "  rubric_version, model_version, created_at)"
            " VALUES (:id, :aid, :v, 0.95, 'test evidence', NULL,"
            "         'judge-rubric-v1', 'anthropic/claude-sonnet-4.6', now())"
        ),
        {"id": str(verdict_id), "aid": str(attack_id), "v": verdict},
    )
    return verdict_id


async def _insert_vulnerability(
    session: AsyncSession,
    *,
    attack_id: UUID,
    verdict_id: UUID,
    target_version_id: UUID,
    status: str,
) -> UUID:
    vuln_id = uuid4()
    await session.execute(
        sa.text(
            "INSERT INTO vulnerabilities"
            " (id, vuln_id, attack_id, verdict_id, severity, title,"
            "  clinical_impact, reproduction_steps, observed_behavior,"
            "  expected_behavior, recommended_remediation, status,"
            "  owasp_llm_id, mitre_atlas_technique_id, hipaa_safeguard,"
            "  framework_versions, target_version_id, created_at, version_id)"
            " VALUES (:id, :vstr, :aid, :vid, 'high', 'Coverage test vuln',"
            "         'synthetic impact', 'synthetic steps', 'observed',"
            "         'expected', 'remediate', :status,"
            "         'LLM01:2025', 'AML.T0051.001', '164.312(a)(1)',"
            "         CAST(:fv AS jsonb), :tvid, now(), 1)"
        ),
        {
            "id": str(vuln_id),
            "vstr": f"VUL-TEST-{vuln_id.hex[:8]}",
            "aid": str(attack_id),
            "vid": str(verdict_id),
            "status": status,
            "fv": '{"owasp_llm": "2025-v2.0", "mitre_atlas": "5.1.0", "hipaa": "2013-omnibus"}',
            "tvid": str(target_version_id),
        },
    )
    return vuln_id


@pytest.mark.asyncio
async def test_snapshot_matches_hand_computed_values(session: AsyncSession) -> None:
    """Seed 3 subcats with known counts; assert each CoverageRow field exactly."""
    target_version_id = await _seed_target_version(session)

    # ---- Subcat A: 10 attacks (judged), 7 exploit + 3 safe, 1 open vuln ----
    a_campaign, a_brief = await _seed_campaign_and_brief(
        session,
        target_version_id=target_version_id,
        subcategory=SUBCAT_A,
    )
    exploit_attack_ids: list[UUID] = []
    for _ in range(7):
        aid = await _insert_attack(
            session,
            campaign_id=a_campaign,
            brief_id=a_brief,
            subcategory=SUBCAT_A,
            category="prompt_injection",
            status="judged",
            executed=True,
        )
        await _insert_verdict(session, attack_id=aid, verdict="exploit")
        exploit_attack_ids.append(aid)
    for _ in range(3):
        aid = await _insert_attack(
            session,
            campaign_id=a_campaign,
            brief_id=a_brief,
            subcategory=SUBCAT_A,
            category="prompt_injection",
            status="judged",
            executed=True,
        )
        await _insert_verdict(session, attack_id=aid, verdict="safe")

    # Attach one vulnerability (status=open) to the first exploit attack.
    # We need its verdict_id; re-query it.
    first_exploit = exploit_attack_ids[0]
    verdict_row = (
        await session.execute(
            sa.text("SELECT id FROM verdicts WHERE attack_id = :aid"),
            {"aid": str(first_exploit)},
        )
    ).first()
    assert verdict_row is not None
    await _insert_vulnerability(
        session,
        attack_id=first_exploit,
        verdict_id=verdict_row[0],
        target_version_id=target_version_id,
        status="open",
    )

    # ---- Subcat B: 5 attacks, all awaiting_judgment, no verdicts, no vulns ----
    b_campaign, b_brief = await _seed_campaign_and_brief(
        session,
        target_version_id=target_version_id,
        subcategory=SUBCAT_B,
    )
    for _ in range(5):
        await _insert_attack(
            session,
            campaign_id=b_campaign,
            brief_id=b_brief,
            subcategory=SUBCAT_B,
            category="data_exfiltration",
            status="awaiting_judgment",
            executed=True,
        )

    # ---- Subcat C: 0 attacks, 0 vulns ----
    # No seed work needed; the taxonomy row already exists from migration 0003.

    # ---- Act ----
    repo = CoverageRepository()
    rows = await repo.snapshot(session, target_version_id=target_version_id)

    by_subcategory = {r.subcategory: r for r in rows}

    # ---- Assert subcat A ----
    a = by_subcategory[SUBCAT_A]
    assert a.category == "prompt_injection"
    assert a.taxonomy_priority is TaxonomyPriority.HIGH
    assert a.attempts == 10
    assert a.exploit_count == 7
    assert a.success_rate == 0.7
    assert a.open_findings_count == 1
    assert a.days_since_last_attempted == 0

    # ---- Assert subcat B ----
    b = by_subcategory[SUBCAT_B]
    assert b.category == "data_exfiltration"
    assert b.taxonomy_priority is TaxonomyPriority.MEDIUM
    assert b.attempts == 5
    assert b.exploit_count == 0
    assert b.success_rate == 0.0
    assert b.open_findings_count == 0
    assert b.days_since_last_attempted == 0

    # ---- Assert subcat C (un-covered) ----
    c = by_subcategory[SUBCAT_C]
    assert c.category == "tool_misuse"
    assert c.taxonomy_priority is TaxonomyPriority.MEDIUM
    assert c.attempts == 0
    assert c.exploit_count == 0
    assert c.success_rate == 0.0
    assert c.open_findings_count == 0
    assert c.days_since_last_attempted is None

    # ---- Sanity: the snapshot is ordered by subcategory and covers every
    # taxonomy row, not just the ones we seeded. ----
    subcategories_in_order = [r.subcategory for r in rows]
    assert subcategories_in_order == sorted(subcategories_in_order)
    assert SUBCAT_A in by_subcategory
    assert SUBCAT_B in by_subcategory
    assert SUBCAT_C in by_subcategory
