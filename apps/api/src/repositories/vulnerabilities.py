"""VulnerabilityRepository — write side for the Documentation Agent.

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

from src.domain.vulnerability import Vulnerability

_VULN_COLS = (
    "id, vuln_id, attack_id, verdict_id, severity, title, clinical_impact,"
    " reproduction_steps, observed_behavior, expected_behavior,"
    " recommended_remediation, status, owasp_llm_id, mitre_atlas_technique_id,"
    " hipaa_safeguard, framework_versions, target_version_id, rubric_snapshot,"
    " created_at, version_id"
)

# A stable advisory lock key for the vuln_id sequence. Postgres advisory
# locks are 64-bit integers; this is the literal "VUL_ID_SEQ" hashed.
_VULN_ID_LOCK: int = 0x56554C49445F534551


class VulnerabilityRepository:
    """Read and write rows in the vulnerabilities table."""

    async def get_by_attack_id(
        self,
        session: AsyncSession,
        attack_id: UUID,
    ) -> Vulnerability | None:
        result = await session.execute(
            sa.text(
                "SELECT id, vuln_id, attack_id, verdict_id, severity, title,"
                "  clinical_impact, reproduction_steps, observed_behavior,"
                "  expected_behavior, recommended_remediation, status,"
                "  owasp_llm_id, mitre_atlas_technique_id, hipaa_safeguard,"
                "  framework_versions, target_version_id, rubric_snapshot,"
                "  created_at, version_id"
                " FROM vulnerabilities WHERE attack_id = :attack_id"
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

        count_row = await session.execute(
            sa.text("SELECT COUNT(*) AS c FROM vulnerabilities")
        )
        count = int(count_row.mappings().first()["c"])  # type: ignore[index]
        vuln_id = f"VUL-{count + 1:04d}"

        result = await session.execute(
            sa.text(
                "INSERT INTO vulnerabilities"
                " (vuln_id, attack_id, verdict_id, severity, title,"
                "  clinical_impact, reproduction_steps, observed_behavior,"
                "  expected_behavior, recommended_remediation, status,"
                "  owasp_llm_id, mitre_atlas_technique_id, hipaa_safeguard,"
                "  framework_versions, target_version_id, rubric_snapshot)"
                " VALUES (:vuln_id, :attack_id, :verdict_id, :severity, :title,"
                "  :impact, :repro, :obs, :exp, :remediation, :status,"
                "  :owasp, :atlas, :hipaa,"
                "  CAST(:fw_versions AS jsonb), :target_version_id,"
                "  CAST(:rubric_snapshot AS jsonb))"
                " RETURNING id, vuln_id, attack_id, verdict_id, severity,"
                "   title, clinical_impact, reproduction_steps,"
                "   observed_behavior, expected_behavior,"
                "   recommended_remediation, status, owasp_llm_id,"
                "   mitre_atlas_technique_id, hipaa_safeguard,"
                "   framework_versions, target_version_id, rubric_snapshot,"
                "   created_at, version_id"
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
                "target_version_id": (
                    str(target_version_id) if target_version_id else None
                ),
                "rubric_snapshot": (
                    json.dumps(rubric_snapshot) if rubric_snapshot is not None else None
                ),
            },
        )
        row = result.mappings().first()
        if row is None:
            raise RuntimeError(
                "vulnerabilities INSERT returned no row — schema or session bug"
            )
        return Vulnerability.model_validate(dict(row))
