"""Arq job for the Documentation Agent.

Co-located with the Red Team / Judge / Orchestrator workers in the same
arq process. The handler runs run_document; the Judge worker enqueues
this job whenever it writes a verdict='exploit' row.

Idempotency (CLAUDE.md §5):
  run_document() short-circuits when a vulnerability already exists for
  the source attack. arq dedup keyed on verdict_id provides a second
  defence.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from src.agents.documentation.document import run_document
from src.domain.vulnerability import VulnerabilityStatus
from src.llm_client.client import LLMClient  # noqa: TC001
from src.observability.context import set_request_id
from src.observability.events import log_event
from src.workers.queue import enqueue_patch_propose


async def write_documentation(
    ctx: dict[str, Any],
    verdict_id: str,
    request_id: str,
) -> dict[str, Any]:
    """Arq job: materialize a vulnerabilities row from an exploit verdict."""
    set_request_id(request_id)

    log_event(
        "documentation_job_started",
        verdict_id=verdict_id,
        outcome="started",
    )

    verdict_uuid = UUID(verdict_id)
    session_factory = ctx["session_factory"]
    llm_client: LLMClient = ctx["llm_client"]

    async with session_factory() as session:
        outcome = await run_document(
            verdict_id=verdict_uuid,
            session=session,
            llm_client=llm_client,
        )
        await session.commit()

    result = {
        "verdict_id": verdict_id,
        "vulnerability_id": (str(outcome.vulnerability_id) if outcome.vulnerability_id else None),
        "vuln_id": outcome.vuln_id,
        "severity": outcome.severity.value if outcome.severity else None,
        "status": outcome.status.value if outcome.status else None,
        "skipped_reason": outcome.skipped_reason,
        "used_fallback": outcome.used_fallback,
    }

    # Slice 5 handoff: enqueue the Patch Agent for non-critical findings.
    # Critical-severity drafts are gated until the operator flips them to
    # 'open' from the UI.
    if outcome.vulnerability_id is not None and outcome.status is VulnerabilityStatus.OPEN:
        await enqueue_patch_propose(outcome.vulnerability_id, request_id)
        log_event(
            "patch_enqueued_from_documentation",
            verdict_id=verdict_id,
            vulnerability_id=str(outcome.vulnerability_id),
            outcome="enqueued",
        )

    log_event(
        "documentation_job_finished",
        verdict_id=verdict_id,
        vulnerability_id=result["vulnerability_id"],
        vuln_id=result["vuln_id"],
        severity=result["severity"],
        status=result["status"],
        used_fallback=outcome.used_fallback,
        skipped_reason=outcome.skipped_reason,
        outcome="success",
    )

    return result
