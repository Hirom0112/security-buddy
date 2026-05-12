"""LangGraph state machine for the Orchestrator.

Single-node graph wrapping run_tick. Future slices may branch the graph
to add coverage-report or scheduling nodes downstream.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002
from typing_extensions import TypedDict

from src.agents.orchestrator.tick import run_tick
from src.llm_client.client import LLMClient  # noqa: TC001


class OrchestratorState(TypedDict):
    """Mutable state flowing through the Orchestrator graph."""

    campaign_id: str
    request_id: str
    brief_id: str | None
    chosen_subcategory: str | None
    used_fallback: bool
    halted_reason: str | None


def build_orchestrator_graph(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    llm_client: LLMClient,
) -> Any:
    """Compile and return the Orchestrator StateGraph."""

    async def tick_node(state: OrchestratorState) -> OrchestratorState:
        campaign_uuid = UUID(state["campaign_id"])
        async with session_factory() as session:
            outcome = await run_tick(
                campaign_id=campaign_uuid,
                session=session,
                llm_client=llm_client,
            )
            await session.commit()

        return OrchestratorState(
            campaign_id=state["campaign_id"],
            request_id=state["request_id"],
            brief_id=str(outcome.brief_id) if outcome.brief_id else None,
            chosen_subcategory=outcome.chosen_subcategory,
            used_fallback=outcome.used_fallback,
            halted_reason=outcome.halted_reason,
        )

    builder: StateGraph[OrchestratorState] = StateGraph(OrchestratorState)
    builder.add_node("tick", tick_node)
    builder.add_edge(START, "tick")
    builder.add_edge("tick", END)

    return builder.compile()
