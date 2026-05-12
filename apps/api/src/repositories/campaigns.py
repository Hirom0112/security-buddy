"""CampaignRepository — data access for campaigns and campaign_briefs tables.

Architectural boundary (import-linter):
  - This module imports from src.domain only.
  - No imports from src.agents, src.llm_client, src.routes, src.workers.

All write operations use optimistic locking via version_id where appropriate.
"""

import json
from decimal import Decimal
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.campaign import Campaign, CampaignBrief, CampaignMode, CampaignStatus
from src.domain.errors import ConflictError, NotFoundError


class CampaignRepository:
    """Read and write campaigns and campaign_briefs rows.

    Methods receive the caller's AsyncSession so that transaction boundaries
    stay with the caller (worker or route handler).
    """

    # ------------------------------------------------------------------
    # Campaign CRUD
    # ------------------------------------------------------------------

    async def create(
        self,
        session: AsyncSession,
        *,
        target_subcategory: str | None,
        budget_usd: Decimal,
        target_version_id: UUID | None = None,
        mode: CampaignMode = CampaignMode.LIVE,
    ) -> Campaign:
        """Insert a new campaign row with status='pending'.

        target_subcategory may be None for empty-start campaigns where the
        Orchestrator picks the subcategory on first tick (Slice 3). For
        manual-trigger campaigns (Slice 1 flow) it must be a valid
        attack_taxonomy.subcategory string.

        mode defaults to LIVE (real, billable, counted on the dashboard).
        Set SMOKE for plumbing checks and CI runs that should not inflate
        coverage or cost stats.

        Returns the newly created Campaign entity.
        """
        result = await session.execute(
            sa.text(
                "INSERT INTO campaigns"
                " (status, mode, budget_usd, target_version_id,"
                "  target_subcategory, created_at, version_id)"
                " VALUES ('pending', :mode, :budget, :version_id,"
                "         :subcategory, now(), 1)"
                " RETURNING id, status, mode, budget_usd, target_version_id,"
                "   target_subcategory, created_at, started_at, completed_at,"
                "   version_id"
            ),
            {
                "mode": mode.value,
                "budget": str(budget_usd),
                "version_id": str(target_version_id) if target_version_id else None,
                "subcategory": target_subcategory,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("INSERT returned no row — this should never happen")
        return Campaign.model_validate(dict(row))

    async def get(
        self,
        session: AsyncSession,
        campaign_id: UUID,
    ) -> Campaign | None:
        """Return the Campaign with the given id, or None if not found."""
        result = await session.execute(
            sa.text(
                "SELECT id, status, mode, budget_usd, target_version_id,"
                "  target_subcategory, created_at, started_at, completed_at,"
                "  version_id"
                " FROM campaigns WHERE id = :id"
            ),
            {"id": str(campaign_id)},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return Campaign.model_validate(dict(row))

    async def update_status(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        status: CampaignStatus,
        expected_version_id: int,
    ) -> Campaign:
        """Update campaign status using optimistic locking.

        Increments version_id on success.
        Raises ConflictError if the current version_id != expected_version_id.
        Raises NotFoundError if the campaign does not exist.
        """
        result = await session.execute(
            sa.text(
                "UPDATE campaigns"
                " SET status = :status, version_id = version_id + 1"
                " WHERE id = :id AND version_id = :expected_version"
                " RETURNING id, status, mode, budget_usd, target_version_id,"
                "   target_subcategory, created_at, started_at, completed_at,"
                "   version_id"
            ),
            {
                "status": status.value,
                "id": str(campaign_id),
                "expected_version": expected_version_id,
            },
        )
        row = result.mappings().first()
        if row is not None:
            return Campaign.model_validate(dict(row))

        # Determine whether it's a not-found or a version conflict.
        check = await session.execute(
            sa.text("SELECT version_id FROM campaigns WHERE id = :id"),
            {"id": str(campaign_id)},
        )
        existing = check.mappings().first()
        if existing is None:
            raise NotFoundError(f"Campaign {campaign_id} not found")
        raise ConflictError(
            f"Campaign {campaign_id} version mismatch: "
            f"expected {expected_version_id}, found {existing['version_id']}"
        )

    async def set_target_subcategory(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        target_subcategory: str,
        expected_version_id: int,
    ) -> Campaign:
        """Set the campaign's target_subcategory via optimistic lock.

        Used by the Orchestrator tick to populate the subcategory chosen by
        the priority function on an empty-start campaign. Increments
        version_id on success.
        """
        result = await session.execute(
            sa.text(
                "UPDATE campaigns"
                " SET target_subcategory = :sub, version_id = version_id + 1"
                " WHERE id = :id AND version_id = :expected_version"
                " RETURNING id, status, mode, budget_usd, target_version_id,"
                "   target_subcategory, created_at, started_at, completed_at,"
                "   version_id"
            ),
            {
                "sub": target_subcategory,
                "id": str(campaign_id),
                "expected_version": expected_version_id,
            },
        )
        row = result.mappings().first()
        if row is not None:
            return Campaign.model_validate(dict(row))

        check = await session.execute(
            sa.text("SELECT version_id FROM campaigns WHERE id = :id"),
            {"id": str(campaign_id)},
        )
        existing = check.mappings().first()
        if existing is None:
            raise NotFoundError(f"Campaign {campaign_id} not found")
        raise ConflictError(
            f"Campaign {campaign_id} version mismatch: "
            f"expected {expected_version_id}, found {existing['version_id']}"
        )

    # ------------------------------------------------------------------
    # CampaignBrief writes
    # ------------------------------------------------------------------

    async def add_brief(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        description: str,
        variant_count: int,
        target_subcategory: str,
        success_criteria: dict[str, object],
        budget_usd: Decimal,
    ) -> CampaignBrief:
        """Insert a campaign_brief row linked to an existing campaign.

        Returns the newly created CampaignBrief entity.
        """
        result = await session.execute(
            sa.text(
                "INSERT INTO campaign_briefs"
                " (campaign_id, target_subcategory, description, variant_count,"
                "  success_criteria, budget_usd, status, created_at)"
                " VALUES (:campaign_id, :subcategory, :description, :variant_count,"
                "  CAST(:criteria AS jsonb), :budget, 'pending', now())"
                " RETURNING id, campaign_id, target_subcategory, description,"
                "   variant_count, success_criteria, budget_usd, status, created_at"
            ),
            {
                "campaign_id": str(campaign_id),
                "subcategory": target_subcategory,
                "description": description,
                "variant_count": variant_count,
                "criteria": json.dumps(success_criteria),
                "budget": str(budget_usd),
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("INSERT returned no row — this should never happen")
        return CampaignBrief.model_validate(dict(row))

    async def get_brief(
        self,
        session: AsyncSession,
        brief_id: UUID,
    ) -> CampaignBrief | None:
        """Return the CampaignBrief with the given id, or None if not found."""
        result = await session.execute(
            sa.text(
                "SELECT id, campaign_id, target_subcategory, description,"
                "  variant_count, success_criteria, budget_usd, status, created_at"
                " FROM campaign_briefs WHERE id = :id"
            ),
            {"id": str(brief_id)},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return CampaignBrief.model_validate(dict(row))
