"""LangGraph state machine for the Documentation Agent.

Single-node StateGraph wrapping run_document so the worker layer stays
graph-agnostic and the graph can later be composed with Patch nodes
downstream (Slice 5).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002
from typing_extensions import TypedDict

from src.agents.documentation.document import run_document
from src.llm_client.client import LLMClient  # noqa: TC001


class DocumentationState(TypedDict):
    """Mutable state flowing through the Documentation graph."""

    verdict_id: str
    request_id: str
    vulnerability_id: str | None
    vuln_id: str | None
    severity: str | None
    status: str | None
    skipped_reason: str | None


def build_documentation_graph(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    llm_client: LLMClient,
) -> Any:
    """Compile and return the Documentation StateGraph."""

    async def document_node(state: DocumentationState) -> DocumentationState:
        verdict_uuid = UUID(state["verdict_id"])
        async with session_factory() as session:
            outcome = await run_document(
                verdict_id=verdict_uuid,
                session=session,
                llm_client=llm_client,
            )
            await session.commit()

        return DocumentationState(
            verdict_id=state["verdict_id"],
            request_id=state["request_id"],
            vulnerability_id=(
                str(outcome.vulnerability_id) if outcome.vulnerability_id else None
            ),
            vuln_id=outcome.vuln_id,
            severity=outcome.severity.value if outcome.severity else None,
            status=outcome.status.value if outcome.status else None,
            skipped_reason=outcome.skipped_reason,
        )

    builder: StateGraph[DocumentationState] = StateGraph(DocumentationState)
    builder.add_node("document", document_node)
    builder.add_edge(START, "document")
    builder.add_edge("document", END)

    return builder.compile()
