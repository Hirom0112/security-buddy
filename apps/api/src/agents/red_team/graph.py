"""LangGraph state machine for the Red Team agent (Slice 1D).

A single-node StateGraph wraps the executor. Future slices will branch this
graph to add Judge, Documentation, and Patch nodes:

    START → execute_red_team → END          (Slice 1D)
    START → execute_red_team → judge → ...  (future slices)

The LangGraph boundary exists so later slices can add nodes without changing
the arq worker or route contracts.

SECURITY (CLAUDE.md §4):
  - No LLM calls in Slice 1D. Mutation is deterministic. llm_client is NOT
    imported here.
  - No shell access, no subprocess.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002
from typing_extensions import TypedDict

from src.agents.red_team.executor import run_executor
from src.agents.red_team.rate_limit import RateLimiter  # noqa: TC001
from src.settings import Settings  # noqa: TC001


class RedTeamState(TypedDict):
    """Mutable state that flows through the Red Team LangGraph.

    All fields are primitive JSON-serialisable types so that LangGraph can
    checkpoint state (Postgres in future slices). No domain entities stored
    here — everything goes through Postgres via IDs.
    """

    brief_id: str
    """UUID of the campaign_brief being executed (string form for JSON compat)."""

    request_id: str
    """Correlation request_id propagated from the FastAPI route."""

    completed_attack_count: int
    """Number of attacks transitioned to awaiting_judgment by this run."""

    halted_reason: str | None
    """If the loop stopped early, the reason string. None on clean completion."""


def build_red_team_graph(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    rate_limiter: RateLimiter,
) -> Any:
    """Compile and return the Red Team StateGraph.

    Args:
        session_factory: SQLAlchemy async session factory injected at build time.
        settings: Application settings injected at build time.
        rate_limiter: Shared outbound rate limiter.

    Returns:
        A compiled LangGraph (CompiledGraph) ready to invoke via
        ``graph.ainvoke(state)``.
    """

    async def execute_red_team_node(state: RedTeamState) -> RedTeamState:
        """LangGraph node: run the Red Team execution loop for state['brief_id']."""
        brief_uuid = UUID(state["brief_id"])

        result = await run_executor(
            brief_id=brief_uuid,
            session_factory=session_factory,
            settings=settings,
            rate_limiter=rate_limiter,
        )

        raw_halted = result.get("halted_reason")
        halted_reason: str | None = raw_halted if isinstance(raw_halted, str) else None
        raw_count = result.get("completed_attack_count", 0)
        completed: int = int(raw_count) if isinstance(raw_count, (int, float)) else 0
        return RedTeamState(
            brief_id=state["brief_id"],
            request_id=state["request_id"],
            completed_attack_count=completed,
            halted_reason=halted_reason,
        )

    builder: StateGraph[RedTeamState] = StateGraph(RedTeamState)
    builder.add_node("execute_red_team", execute_red_team_node)
    builder.add_edge(START, "execute_red_team")
    builder.add_edge("execute_red_team", END)

    return builder.compile()
