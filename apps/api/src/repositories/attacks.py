"""AttackRepository — data access for the attacks table.

Architectural boundary (import-linter):
  - This module imports from src.domain only.
  - No imports from src.agents, src.llm_client, src.routes, src.workers.

All writes are idempotent:
  - create_pending uses a unique constraint on (brief_id, variant_index)
    (implemented as a partial unique index expected in schema) with
    ON CONFLICT DO NOTHING. Since the schema only has a primary-key
    unique constraint on id, we use a two-step check: SELECT first, then INSERT,
    wrapped in an advisory lock via a status guard to prevent double-write
    on retry.

NOTE: The schema does NOT have a (brief_id, variant_index) unique constraint.
We approximate idempotency by reading attack_metadata->>'variant_index' and
doing a SELECT before INSERT. For true idempotency in the face of concurrent
retries, callers must ensure only one worker processes a given brief at a time
(enforced via Redis-arq job deduplication in the worker layer).
"""

import json
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.attack import Attack
from src.domain.errors import NotFoundError


class AttackRepository:
    """Read and write attacks rows.

    Methods receive the caller's AsyncSession so that transaction boundaries
    stay with the caller (worker or route handler).
    """

    async def create_pending(
        self,
        session: AsyncSession,
        *,
        campaign_id: UUID,
        brief_id: UUID,
        category: str,
        subcategory: str,
        mutation_strategy: str,
        seed_used: str | None,
        attack_input: str,
        attack_metadata: dict[str, str | int | bool],
    ) -> Attack:
        """Insert a new attack row with status='pending_execution'.

        Idempotency: if an attack with the same (brief_id, variant_index
        from metadata) already exists, return the existing row without
        inserting a duplicate. variant_index must be present in attack_metadata.

        Returns the Attack entity (newly inserted or the existing one).
        """
        variant_index: int | None = None
        raw_idx = attack_metadata.get("variant_index")
        if isinstance(raw_idx, int):
            variant_index = raw_idx

        # Idempotency check: if a row with this brief_id + variant_index exists,
        # return it without inserting a duplicate.
        if variant_index is not None:
            existing = await self._find_by_brief_and_variant(
                session, brief_id=brief_id, variant_index=variant_index
            )
            if existing is not None:
                return existing

        result = await session.execute(
            sa.text(
                "INSERT INTO attacks"
                " (campaign_id, brief_id, category, subcategory, mutation_strategy,"
                "  seed_used, attack_input, attack_metadata, status, created_at)"
                " VALUES (:campaign_id, :brief_id, :category, :subcategory,"
                "  :mutation_strategy, :seed_used, :attack_input,"
                "  CAST(:metadata AS jsonb), 'pending_execution', now())"
                " RETURNING id, campaign_id, brief_id, category, subcategory,"
                "   mutation_strategy, seed_used, attack_input, attack_metadata,"
                "   target_response, target_response_status,"
                "   target_response_time_ms, status, created_at, executed_at"
            ),
            {
                "campaign_id": str(campaign_id),
                "brief_id": str(brief_id),
                "category": category,
                "subcategory": subcategory,
                "mutation_strategy": mutation_strategy,
                "seed_used": seed_used,
                "attack_input": attack_input,
                "metadata": json.dumps(attack_metadata),
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("INSERT returned no row — this should never happen")
        return Attack.model_validate(dict(row))

    async def mark_awaiting_judgment(
        self,
        session: AsyncSession,
        *,
        attack_id: UUID,
        target_response: str,
        target_response_status: int,
        target_response_time_ms: int,
    ) -> Attack:
        """Transition attack to awaiting_judgment with the stored response.

        Idempotent: if already awaiting_judgment (e.g. retry after crash),
        returns the existing row without writing. If already judged, returns
        the existing row — callers must not re-judge a completed attack.

        Raises NotFoundError if the attack does not exist.
        """
        result = await session.execute(
            sa.text(
                "UPDATE attacks"
                " SET target_response = :response,"
                "     target_response_status = :status,"
                "     target_response_time_ms = :time_ms,"
                "     executed_at = now(),"
                "     status = 'awaiting_judgment'"
                " WHERE id = :id AND status = 'pending_execution'"
                " RETURNING id, campaign_id, brief_id, category, subcategory,"
                "   mutation_strategy, seed_used, attack_input, attack_metadata,"
                "   target_response, target_response_status,"
                "   target_response_time_ms, status, created_at, executed_at"
            ),
            {
                "response": target_response,
                "status": target_response_status,
                "time_ms": target_response_time_ms,
                "id": str(attack_id),
            },
        )
        row = result.mappings().first()
        if row is not None:
            return Attack.model_validate(dict(row))

        # The UPDATE matched nothing. Either it doesn't exist or it's already
        # in a later status (awaiting_judgment or judged). Return existing.
        existing = await self._get_by_id(session, attack_id)
        if existing is None:
            raise NotFoundError(f"Attack {attack_id} not found")
        return existing

    async def mark_target_unavailable(
        self,
        session: AsyncSession,
        *,
        attack_id: UUID,
        error: str,
    ) -> Attack:
        """Transition attack to target_unavailable status.

        error is stored as a JSON field in attack_metadata['target_error'].
        Idempotent: if already in a terminal-equivalent status, returns
        the existing row.

        Raises NotFoundError if the attack does not exist.
        """
        result = await session.execute(
            sa.text(
                "UPDATE attacks"
                " SET status = 'target_unavailable',"
                "     executed_at = COALESCE(executed_at, now()),"
                "     attack_metadata = attack_metadata || "
                "       jsonb_build_object('target_error', CAST(:error AS text))"
                " WHERE id = :id AND status = 'pending_execution'"
                " RETURNING id, campaign_id, brief_id, category, subcategory,"
                "   mutation_strategy, seed_used, attack_input, attack_metadata,"
                "   target_response, target_response_status,"
                "   target_response_time_ms, status, created_at, executed_at"
            ),
            {"error": error, "id": str(attack_id)},
        )
        row = result.mappings().first()
        if row is not None:
            return Attack.model_validate(dict(row))

        existing = await self._get_by_id(session, attack_id)
        if existing is None:
            raise NotFoundError(f"Attack {attack_id} not found")
        return existing

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get_by_id(
        self,
        session: AsyncSession,
        attack_id: UUID,
    ) -> Attack | None:
        result = await session.execute(
            sa.text(
                "SELECT id, campaign_id, brief_id, category, subcategory,"
                "  mutation_strategy, seed_used, attack_input, attack_metadata,"
                "  target_response, target_response_status,"
                "  target_response_time_ms, status, created_at, executed_at"
                " FROM attacks WHERE id = :id"
            ),
            {"id": str(attack_id)},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return Attack.model_validate(dict(row))

    async def _find_by_brief_and_variant(
        self,
        session: AsyncSession,
        *,
        brief_id: UUID,
        variant_index: int,
    ) -> Attack | None:
        """Find an existing attack row by brief_id + variant_index metadata."""
        result = await session.execute(
            sa.text(
                "SELECT id, campaign_id, brief_id, category, subcategory,"
                "  mutation_strategy, seed_used, attack_input, attack_metadata,"
                "  target_response, target_response_status,"
                "  target_response_time_ms, status, created_at, executed_at"
                " FROM attacks"
                " WHERE brief_id = :brief_id"
                "   AND (attack_metadata->>'variant_index')::int = :variant_index"
                " LIMIT 1"
            ),
            {"brief_id": str(brief_id), "variant_index": variant_index},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return Attack.model_validate(dict(row))
