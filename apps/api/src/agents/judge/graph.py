"""LangGraph state machine for the Judge agent.

Single-node StateGraph wrapping run_judge so the worker layer stays
graph-agnostic and the graph can later be composed with Documentation/Patch
nodes downstream.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker  # noqa: TC002
from typing_extensions import TypedDict

from src.agents.judge.judge import run_judge
from src.llm_client.client import LLMClient  # noqa: TC001


class JudgeState(TypedDict):
    """Mutable state flowing through the Judge graph."""

    attack_id: str
    request_id: str
    verdict_id: str | None
    verdict: str | None
    skipped_reason: str | None


def build_judge_graph(
    *,
    session_factory: async_sessionmaker[AsyncSession],
    llm_client: LLMClient,
) -> Any:
    """Compile and return the Judge StateGraph."""

    async def judge_node(state: JudgeState) -> JudgeState:
        attack_uuid = UUID(state["attack_id"])
        async with session_factory() as session:
            outcome = await run_judge(
                attack_id=attack_uuid,
                session=session,
                llm_client=llm_client,
            )
            await session.commit()

        return JudgeState(
            attack_id=state["attack_id"],
            request_id=state["request_id"],
            verdict_id=str(outcome.verdict_id),
            verdict=outcome.verdict.value,
            skipped_reason=outcome.skipped_reason,
        )

    builder: StateGraph[JudgeState] = StateGraph(JudgeState)
    builder.add_node("judge", judge_node)
    builder.add_edge(START, "judge")
    builder.add_edge("judge", END)

    return builder.compile()
