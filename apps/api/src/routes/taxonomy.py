"""GET /api/v1/attack_taxonomy — surface map for the Start Campaign modal.

Returns a category→[subcategories] tree the UI's cascading dropdown
consumes. The route is read-only and uses a single SELECT with no joins;
the per-request cost is negligible for the single-operator workload.

We deliberately do not page this endpoint — the seeded taxonomy has on
the order of dozens of rows, not thousands. If the taxonomy ever grows
past ~500 rows, switch to keyset pagination.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator  # noqa: TC003
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002

router = APIRouter(prefix="/api/v1", tags=["taxonomy"])


async def _get_session_factory(
    request: Request,
) -> async_sessionmaker[AsyncSession]:
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    return factory


async def _get_db_session(
    factory: Annotated[async_sessionmaker[AsyncSession], Depends(_get_session_factory)],
) -> AsyncGenerator[AsyncSession, None]:
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


class TaxonomyCategory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str
    subcategories: list[str]


class AttackTaxonomyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    categories: list[TaxonomyCategory]


@router.get(
    "/attack_taxonomy",
    response_model=AttackTaxonomyResponse,
    summary="Return the category→subcategories tree (UI dropdown source)",
)
async def get_attack_taxonomy(
    session: Annotated[AsyncSession, Depends(_get_db_session)],
) -> AttackTaxonomyResponse:
    result = await session.execute(
        sa.text(
            "SELECT category, subcategory FROM attack_taxonomy"
            " ORDER BY category ASC, subcategory ASC"
        )
    )
    by_category: dict[str, list[str]] = {}
    for row in result.mappings():
        cat = str(row["category"])
        sub = str(row["subcategory"])
        by_category.setdefault(cat, []).append(sub)

    return AttackTaxonomyResponse(
        categories=[
            TaxonomyCategory(category=c, subcategories=subs) for c, subs in by_category.items()
        ]
    )
