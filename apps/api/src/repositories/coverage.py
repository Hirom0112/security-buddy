"""CoverageRepository — aggregate queries for the Orchestrator's priority math.

Architectural boundary (import-linter):
  - Imports from src.domain only.
  - No imports from src.agents, src.llm_client, src.routes, src.workers.

All queries are scoped to the **current target version** when one is provided
so the priority decision reflects coverage against the live system, not
historical coverage against earlier versions. When target_version_id is None
(no deployed target yet, or pre-Slice-6 scaffolding) all attempts are
considered.
"""

from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.coverage import CoverageRow, TaxonomyPriority

_COVERAGE_SQL = """
WITH attempts_by_sub AS (
    SELECT
        a.subcategory,
        COUNT(*) FILTER (
            WHERE CAST(:version_id AS uuid) IS NULL OR c.target_version_id = :version_id
        ) AS attempts,
        COUNT(*) FILTER (
            WHERE v.verdict = 'exploit'
              AND (CAST(:version_id AS uuid) IS NULL OR c.target_version_id = :version_id)
        ) AS exploit_count,
        MAX(a.executed_at) FILTER (
            WHERE CAST(:version_id AS uuid) IS NULL OR c.target_version_id = :version_id
        ) AS last_attempted_at
    FROM attacks a
    JOIN campaigns c ON c.id = a.campaign_id
    LEFT JOIN verdicts v ON v.attack_id = a.id
    GROUP BY a.subcategory
),
open_findings_by_sub AS (
    SELECT
        a.subcategory,
        COUNT(*) AS open_findings_count
    FROM vulnerabilities vu
    JOIN attacks a ON a.id = vu.attack_id
    WHERE vu.status IN ('open','regressed')
    GROUP BY a.subcategory
)
SELECT
    t.category,
    t.subcategory,
    t.priority AS taxonomy_priority,
    COALESCE(att.attempts, 0) AS attempts,
    COALESCE(att.exploit_count, 0) AS exploit_count,
    COALESCE(ofs.open_findings_count, 0) AS open_findings_count,
    CASE
        WHEN att.last_attempted_at IS NULL THEN NULL
        ELSE GREATEST(0, EXTRACT(DAY FROM (now() - att.last_attempted_at))::int)
    END AS days_since_last_attempted
FROM attack_taxonomy t
LEFT JOIN attempts_by_sub att ON att.subcategory = t.subcategory
LEFT JOIN open_findings_by_sub ofs ON ofs.subcategory = t.subcategory
ORDER BY t.subcategory
"""


class CoverageRepository:
    """Read-only aggregate queries over the taxonomy + attack history."""

    async def snapshot(
        self,
        session: AsyncSession,
        *,
        target_version_id: UUID | None = None,
    ) -> list[CoverageRow]:
        """Return one CoverageRow per subcategory in attack_taxonomy.

        Scoped to the given target_version_id when provided. The result is
        deterministic (ordered by subcategory) so tests and audit logs are
        reproducible.
        """
        result = await session.execute(
            sa.text(_COVERAGE_SQL),
            {"version_id": str(target_version_id) if target_version_id else None},
        )
        rows: list[CoverageRow] = []
        for row in result.mappings().all():
            rows.append(
                CoverageRow(
                    category=row["category"],
                    subcategory=row["subcategory"],
                    taxonomy_priority=TaxonomyPriority(row["taxonomy_priority"]),
                    attempts=int(row["attempts"]),
                    exploit_count=int(row["exploit_count"]),
                    open_findings_count=int(row["open_findings_count"]),
                    days_since_last_attempted=(
                        int(row["days_since_last_attempted"])
                        if row["days_since_last_attempted"] is not None
                        else None
                    ),
                )
            )
        return rows
