"""AttackTaxonomyRepository — read framework mappings for a subcategory.

Tiny repo dedicated to the Documentation Agent's framework-citation lookup
(CLAUDE.md §6a). Kept separate from CoverageRepository so the SQL
responsibilities stay narrow.
"""

from typing import Any

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession


class AttackTaxonomyRepository:
    """Read-only lookups against attack_taxonomy."""

    async def get_framework_for_subcategory(
        self,
        session: AsyncSession,
        subcategory: str,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        """Return (framework_mappings, framework_versions) for a subcategory.

        Returns None when the subcategory is not in attack_taxonomy.
        """
        result = await session.execute(
            sa.text(
                "SELECT framework_mappings, framework_versions"
                " FROM attack_taxonomy WHERE subcategory = :sub"
            ),
            {"sub": subcategory},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return dict(row["framework_mappings"]), dict(row["framework_versions"])
