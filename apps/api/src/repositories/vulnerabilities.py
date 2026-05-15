"""VulnerabilityRepository — write side for the Documentation Agent.

Slice 5 adds get_by_id() and update_status() for the Patch Agent and the
operator-facing patches route.

Architectural boundary (import-linter): imports from src.domain only.

Idempotency:
  - Unique on vuln_id ("VUL-NNNN") and one-finding-per-attack via the
    UNIQUE (attack_id) index we add at write time (see migration 0005).
  - generate_vuln_id() uses SELECT COUNT + 1 inside the same transaction;
    callers must hold the row-level write lock (default REPEATABLE READ
    or use a Postgres advisory lock) to avoid duplicate sequence allocation
    under concurrent inserts. The Documentation worker uses arq job dedup
    on verdict_id so concurrent allocation is unlikely; we still take the
    advisory lock as belt-and-suspenders.

The repository writes the structured columns; the Markdown report itself
is rendered separately via agents.documentation.template.render_markdown
and stored in the UI / GitHub PR body, not in the DB.
"""

import json
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.vulnerability import Vulnerability, VulnerabilityStatus

_VULN_COLS = (
    "id, vuln_id, attack_id, verdict_id, severity, title, clinical_impact,"
    " reproduction_steps, observed_behavior, expected_behavior,"
    " recommended_remediation, status, owasp_llm_id, mitre_atlas_technique_id,"
    " hipaa_safeguard, framework_versions, target_version_id, rubric_snapshot,"
    " created_at, version_id, notes,"
    " response_shape_hash, variant_count, variant_of_vuln_id"
)

# A stable advisory lock key for the vuln_id sequence. Postgres advisory
# locks are signed 64-bit integers; this is the literal "VULIDSEQ"
# (8 bytes, fits in int64). The earlier "VUL_ID_SEQ" packed to 9 bytes
# which overflowed the bigint parameter and broke vuln creation.
_VULN_ID_LOCK: int = 0x56554C4944534551


class VulnerabilityRepository:
    """Read and write rows in the vulnerabilities table."""

    async def get_by_attack_id(
        self,
        session: AsyncSession,
        attack_id: UUID,
    ) -> Vulnerability | None:
        result = await session.execute(
            sa.text(
                f"SELECT {_VULN_COLS} FROM vulnerabilities"  # noqa: S608
                " WHERE attack_id = :attack_id"
                " ORDER BY created_at ASC LIMIT 1"
            ),
            {"attack_id": str(attack_id)},
        )
        row = result.mappings().first()
        if row is None:
            return None
        return Vulnerability.model_validate(dict(row))

    async def create(
        self,
        session: AsyncSession,
        *,
        attack_id: UUID,
        verdict_id: UUID,
        severity: str,
        title: str,
        clinical_impact: str,
        reproduction_steps: str,
        observed_behavior: str,
        expected_behavior: str,
        recommended_remediation: str,
        status: str,
        owasp_llm_id: str,
        mitre_atlas_technique_id: str,
        hipaa_safeguard: str,
        framework_versions: dict[str, Any],
        target_version_id: UUID | None,
        rubric_snapshot: dict[str, Any] | None,
        response_shape_hash: str | None = None,
    ) -> Vulnerability:
        """Insert a vulnerabilities row.

        Idempotent on (attack_id): if a vulnerability already exists for the
        attack, returns the existing row without modification. The unique
        constraint is NOT in the schema (an attack could theoretically have
        multiple reports if the rubric changes), but the Documentation
        worker is the only writer and it queues one job per verdict — so
        this method enforces 'first writer wins' at the application layer.
        """
        existing = await self.get_by_attack_id(session, attack_id)
        if existing is not None:
            return existing

        # Acquire a transaction-scoped advisory lock so concurrent inserts
        # don't both compute the same vuln_id sequence number.
        await session.execute(
            sa.text("SELECT pg_advisory_xact_lock(:k)"),
            {"k": _VULN_ID_LOCK},
        )

        count_row = await session.execute(sa.text("SELECT COUNT(*) AS c FROM vulnerabilities"))
        count = int(count_row.mappings().first()["c"])  # type: ignore[index]
        vuln_id = f"VUL-{count + 1:04d}"

        result = await session.execute(
            sa.text(
                "INSERT INTO vulnerabilities"  # noqa: S608
                " (vuln_id, attack_id, verdict_id, severity, title,"
                "  clinical_impact, reproduction_steps, observed_behavior,"
                "  expected_behavior, recommended_remediation, status,"
                "  owasp_llm_id, mitre_atlas_technique_id, hipaa_safeguard,"
                "  framework_versions, target_version_id, rubric_snapshot,"
                "  response_shape_hash)"
                " VALUES (:vuln_id, :attack_id, :verdict_id, :severity, :title,"
                "  :impact, :repro, :obs, :exp, :remediation, :status,"
                "  :owasp, :atlas, :hipaa,"
                "  CAST(:fw_versions AS jsonb), :target_version_id,"
                "  CAST(:rubric_snapshot AS jsonb),"
                "  :response_shape_hash)"
                f" RETURNING {_VULN_COLS}"
            ),
            {
                "vuln_id": vuln_id,
                "attack_id": str(attack_id),
                "verdict_id": str(verdict_id),
                "severity": severity,
                "title": title,
                "impact": clinical_impact,
                "repro": reproduction_steps,
                "obs": observed_behavior,
                "exp": expected_behavior,
                "remediation": recommended_remediation,
                "status": status,
                "owasp": owasp_llm_id,
                "atlas": mitre_atlas_technique_id,
                "hipaa": hipaa_safeguard,
                "fw_versions": json.dumps(framework_versions),
                "target_version_id": (str(target_version_id) if target_version_id else None),
                "rubric_snapshot": (
                    json.dumps(rubric_snapshot) if rubric_snapshot is not None else None
                ),
                "response_shape_hash": response_shape_hash,
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError("vulnerabilities INSERT returned no row — schema or session bug")
        return Vulnerability.model_validate(dict(row))

    async def get_by_id(
        self,
        session: AsyncSession,
        vulnerability_id: UUID,
    ) -> Vulnerability | None:
        result = await session.execute(
            sa.text(
                f"SELECT {_VULN_COLS} FROM vulnerabilities WHERE id = :id"  # noqa: S608
            ),
            {"id": str(vulnerability_id)},
        )
        row = result.mappings().first()
        return Vulnerability.model_validate(dict(row)) if row else None

    async def append_note(
        self,
        session: AsyncSession,
        *,
        vulnerability_id: UUID,
        note: dict[str, Any],
        expected_version_id: int | None = None,
    ) -> Vulnerability | None:
        """Append a JSON entry to vulnerabilities.notes (audit trail).

        Optimistic-locked: if expected_version_id is provided, the UPDATE
        only fires when the row still carries that version. Returns None
        when the row is missing or the version check fails — the route
        translates that into a 409 Conflict.

        The note is appended via jsonb `||` so concurrent appenders cannot
        clobber each other's entries (we always read-then-rewrite when
        using JSON parsing, vs. jsonb concat is server-side).
        """
        params: dict[str, Any] = {
            "id": str(vulnerability_id),
            "note": json.dumps(note),
        }
        where = "id = :id"
        if expected_version_id is not None:
            where += " AND version_id = :v"
            params["v"] = expected_version_id

        result = await session.execute(
            sa.text(
                "UPDATE vulnerabilities"  # noqa: S608
                " SET notes = notes || CAST(:note AS jsonb),"
                "     version_id = version_id + 1"
                f" WHERE {where}"
                f" RETURNING {_VULN_COLS}"
            ),
            params,
        )
        row = result.mappings().first()
        return Vulnerability.model_validate(dict(row)) if row else None

    async def find_existing_variant(
        self,
        session: AsyncSession,
        *,
        subcategory: str,
        response_shape_hash: str,
        target_version_id: UUID | None,
    ) -> Vulnerability | None:
        """Find a draft/open vulnerability with the same response shape.

        Filters by subcategory + response_shape_hash + target_version_id.
        target_version_id scopes the window: when the target redeploys, hashes
        get reconsidered fresh (new target_version_id -> no match -> mint).

        Only matches rows whose status is still actionable (draft|open). A
        patched/regressed/over_fit row is a historical record; a fresh sibling
        attack should still mint independently so the regression harness can
        do its job.

        Cross-subcategory join: joins to `attacks` on attack_id so the
        subcategory filter holds even when the same shape appears under a
        different subcategory (we want NO cross-subcategory dedup — that
        would mask a genuinely different bug class).
        """
        result = await session.execute(
            sa.text(
                f"SELECT {_VULN_COLS} FROM vulnerabilities AS v"  # noqa: S608
                " JOIN attacks AS a ON a.id = v.attack_id"
                " WHERE v.response_shape_hash = :h"
                "   AND a.subcategory = :sub"
                "   AND v.status IN ('draft','open')"
                "   AND ("
                "        (:tvid IS NULL AND v.target_version_id IS NULL)"
                "     OR v.target_version_id = CAST(:tvid AS uuid)"
                "   )"
                " ORDER BY v.created_at ASC"
                " LIMIT 1"
            ),
            {
                "h": response_shape_hash,
                "sub": subcategory,
                "tvid": str(target_version_id) if target_version_id else None,
            },
        )
        row = result.mappings().first()
        if row is None:
            return None
        return Vulnerability.model_validate(dict(row))

    async def increment_variant_count(
        self,
        session: AsyncSession,
        *,
        vulnerability_id: UUID,
        merge_note: dict[str, Any],
    ) -> Vulnerability | None:
        """Bump variant_count and append a merged-variant note in one UPDATE.

        Used by the Documentation Agent when a sibling attack hashes
        identically to an existing draft/open vuln. We never mint a second
        VUL-NNNN row in that case.
        """
        result = await session.execute(
            sa.text(
                "UPDATE vulnerabilities"  # noqa: S608
                " SET variant_count = variant_count + 1,"
                "     notes = notes || CAST(:note AS jsonb),"
                "     version_id = version_id + 1"
                " WHERE id = :id"
                f" RETURNING {_VULN_COLS}"
            ),
            {
                "id": str(vulnerability_id),
                "note": json.dumps(merge_note),
            },
        )
        row = result.mappings().first()
        return Vulnerability.model_validate(dict(row)) if row else None

    async def update_status(
        self,
        session: AsyncSession,
        *,
        vulnerability_id: UUID,
        new_status: VulnerabilityStatus,
    ) -> Vulnerability | None:
        """Optimistic-locked status transition. Returns the new row, or None."""
        result = await session.execute(
            sa.text(
                "UPDATE vulnerabilities"  # noqa: S608
                " SET status = :s, version_id = version_id + 1"
                " WHERE id = :id"
                f" RETURNING {_VULN_COLS}"
            ),
            {"id": str(vulnerability_id), "s": new_status.value},
        )
        row = result.mappings().first()
        return Vulnerability.model_validate(dict(row)) if row else None
