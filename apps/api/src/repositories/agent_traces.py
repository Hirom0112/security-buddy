"""AgentTracesRepository — cost queries for the Orchestrator's budget enforcer.

Slice 0's llm_client wraps the trace persistence (currently stubbed). When
that wiring lands, this repository provides the read side: aggregate
cost_usd by campaign and by agent.

Architectural boundary (import-linter):
  - Imports from src.domain only.
"""

from decimal import Decimal
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession


class AgentTracesRepository:
    """Read-only aggregates over agent_traces."""

    async def total_cost_for_campaign(
        self,
        session: AsyncSession,
        campaign_id: UUID,
    ) -> Decimal:
        """Return the sum of cost_usd for every trace in this campaign.

        Returns Decimal('0') when the campaign has no traces yet — including
        the Slice-1 case where the Red Team made no LLM calls. Decimal is
        used end-to-end so accumulated sub-cent fractions don't drift.
        """
        result = await session.execute(
            sa.text(
                "SELECT COALESCE(SUM(cost_usd), 0) AS total"
                " FROM agent_traces"
                " WHERE campaign_id = :campaign_id"
            ),
            {"campaign_id": str(campaign_id)},
        )
        row = result.mappings().first()
        if row is None:
            return Decimal("0")
        raw = row["total"]
        return Decimal(str(raw)) if not isinstance(raw, Decimal) else raw
