"""VerdictRepository — data access for the verdicts table.

Architectural boundary (import-linter):
  - This module imports from src.domain only.
  - No imports from src.agents, src.llm_client, src.routes, src.workers.

Idempotency contract:
  - verdicts.attack_id has a UNIQUE constraint (uq_verdicts_attack_id).
  - create() uses ON CONFLICT (attack_id) DO NOTHING + a fallback SELECT,
    returning the existing row on conflict. A re-run of judge.evaluate
    writes zero new rows.
"""

from decimal import Decimal
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.verdict import Verdict


class VerdictRepository:
    """Read and write rows in the verdicts table."""

    async def get_by_attack_id(
        self,
        session: AsyncSession,
        attack_id: UUID,
    ) -> Verdict | None:
        """Return the verdict for an attack, or None.

        Unique constraint guarantees at most one row.
        """
        result = await session.execute(
            sa.text(
                "SELECT id, attack_id, verdict, confidence, evidence, notes,"
                "  rubric_version, model_version, created_at,"
                "  data_actually_disclosed"
                " FROM verdicts WHERE attack_id = :attack_id"
            ),
            {"attack_id": str(attack_id)},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return Verdict.model_validate(dict(row))

    async def create(
        self,
        session: AsyncSession,
        *,
        attack_id: UUID,
        verdict: str,
        confidence: Decimal,
        evidence: str,
        notes: str | None,
        rubric_version: str,
        model_version: str,
        data_actually_disclosed: bool | None = None,
    ) -> Verdict:
        """Insert a verdict row.

        Idempotent via ON CONFLICT (attack_id) DO NOTHING: if a verdict
        already exists for this attack, returns the existing row without
        modification. Re-judging is not permitted.
        """
        # INSERT ... ON CONFLICT DO NOTHING returns no row on conflict, so
        # we wrap in a CTE that UNIONs the new row with a fallback SELECT
        # against verdicts when the INSERT did nothing.
        result = await session.execute(
            sa.text(
                "WITH ins AS ("
                "  INSERT INTO verdicts"
                "    (attack_id, verdict, confidence, evidence, notes,"
                "     rubric_version, model_version, data_actually_disclosed)"
                "  VALUES (:attack_id, :verdict, :confidence, :evidence, :notes,"
                "          :rubric_version, :model_version, :data_actually_disclosed)"
                "  ON CONFLICT (attack_id) DO NOTHING"
                "  RETURNING id, attack_id, verdict, confidence, evidence,"
                "    notes, rubric_version, model_version, created_at,"
                "    data_actually_disclosed"
                ")"
                "SELECT id, attack_id, verdict, confidence, evidence,"
                "  notes, rubric_version, model_version, created_at,"
                "  data_actually_disclosed FROM ins"
                " UNION ALL "
                "SELECT id, attack_id, verdict, confidence, evidence,"
                "  notes, rubric_version, model_version, created_at,"
                "  data_actually_disclosed"
                " FROM verdicts"
                " WHERE attack_id = :attack_id AND NOT EXISTS (SELECT 1 FROM ins)"
            ),
            {
                "attack_id": str(attack_id),
                "verdict": verdict,
                "confidence": confidence,
                "evidence": evidence,
                "notes": notes,
                "rubric_version": rubric_version,
                "model_version": model_version,
                "data_actually_disclosed": data_actually_disclosed,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("verdicts upsert returned no row — schema or session bug")
        return Verdict.model_validate(dict(row))

    async def mark_replay_unstable(
        self,
        session: AsyncSession,
        *,
        verdict_id: UUID,
        evidence: str,
    ) -> Verdict | None:
        """Flip a verdict to verdict='replay_unstable' (terminal).

        Called by the Documentation Agent's pre-write replay validation when
        the source attack does not reproduce. The row is preserved as an
        audit record; the new verdict label keeps it out of the documentation
        pipeline on retry. See migration 0013.
        """
        result = await session.execute(
            sa.text(
                "UPDATE verdicts SET verdict = 'replay_unstable',"
                "  evidence = :evidence"
                " WHERE id = :id"
                " RETURNING id, attack_id, verdict, confidence, evidence,"
                "   notes, rubric_version, model_version, created_at,"
                "   data_actually_disclosed"
            ),
            {"id": str(verdict_id), "evidence": evidence[:1000]},
        )
        row = result.mappings().first()
        return Verdict.model_validate(dict(row)) if row else None
