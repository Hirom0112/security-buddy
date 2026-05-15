"""Real replay function for the regression worker.

Fires the original attack input against the live target, then asks the
Judge LLM to label the response. Returns a ReplayResult the runner can
aggregate.

This module is the *only* place in the harness/ package that does I/O
against the target or the LLM. The pure aggregation logic lives in
harness.aggregate; harness.runner is dependency-injected over a callable
so it can be unit-tested without this module.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.agents.judge.model import JUDGE_AGENT_TAG, JUDGE_MODEL
from src.agents.judge.parse import parse_judgment
from src.agents.judge.prompt import build_judge_messages
from src.agents.judge.rubric import resolve_rubric
from src.agents.red_team.target_client import (
    TargetClient,
    TargetRateLimitedError,
    TargetUnavailableError,
)
from src.domain.verdict import VerdictLabel
from src.harness.runner import ReplayCallable, ReplayInput, ReplayResult
from src.observability.events import log_event
from src.repositories.attacks import AttackRepository
from src.repositories.target_manifests import TargetManifestRepository

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.llm_client.client import LLMClient


def make_live_replay(
    *,
    session: AsyncSession,
    target_client: TargetClient,
    llm_client: LLMClient,
) -> ReplayCallable:
    """Build a ReplayCallable bound to a live target + LLM client.

    Returned as a closure so the runner stays decoupled from infra wiring.
    """

    async def _replay(inp: ReplayInput) -> ReplayResult:
        # ----------------------------------------------------------
        # 1. Recover the original attack metadata we need for rubric
        #    resolution + target-call accounting.
        # ----------------------------------------------------------
        attack = await AttackRepository().get_by_id(session, inp.attack_id)
        if attack is None:
            return ReplayResult(
                verdict=VerdictLabel.UNCLEAR,
                evidence="source attack row missing",
                target_status_code=None,
                target_unavailable=True,
            )
        manifest = await TargetManifestRepository().get_active(session)
        if manifest is None:
            return ReplayResult(
                verdict=VerdictLabel.UNCLEAR,
                evidence="target manifest missing",
                target_status_code=None,
                target_unavailable=True,
            )

        # ----------------------------------------------------------
        # 2. Re-fire against the target.
        # ----------------------------------------------------------
        meta_pids = attack.attack_metadata.get("patient_ids", [])
        patient_ids = [str(p) for p in meta_pids] if isinstance(meta_pids, list) else []
        try:
            response = await target_client.fire_query(
                message=inp.attack_input,
                attack_id=inp.attack_id,
                campaign_id=attack.campaign_id,
                patient_ids=patient_ids,
            )
        except (TargetUnavailableError, TargetRateLimitedError) as exc:
            log_event(
                "harness_target_unavailable",
                vulnerability_id=str(inp.vulnerability_id),
                attack_id=str(inp.attack_id),
                error_class=type(exc).__name__,
                outcome="target_unavailable",
            )
            return ReplayResult(
                verdict=VerdictLabel.UNCLEAR,
                evidence=f"target unavailable: {type(exc).__name__}",
                target_status_code=None,
                target_unavailable=True,
            )

        # ----------------------------------------------------------
        # 3. Judge the response with the current rubric.
        #    NOTE: the Slice-6 plan calls for using the frozen rubric
        #    from inp.rubric_snapshot. The current rubric_snapshot
        #    column only carries rubric_version + violated_boundary_ids;
        #    a full frozen-rubric snapshot is tracked as a follow-up in
        #    TODO.md ("Watch items: Slice 6 frozen rubric"). For now we
        #    resolve against the live manifest so the harness has *some*
        #    rubric to use.
        # ----------------------------------------------------------
        rubric = resolve_rubric(
            manifest_json=manifest.manifest_json,
            subcategory=attack.subcategory,
            success_criteria={},
        )
        messages = build_judge_messages(
            rubric=rubric,
            attack_input=inp.attack_input,
            target_response=(response.narrative or response.response_body or ""),
            target_response_status=response.status_code,
        )
        completion = await llm_client.complete(
            model=JUDGE_MODEL,
            messages=messages,
            agent=JUDGE_AGENT_TAG,
            campaign_id=attack.campaign_id,
            attack_id=inp.attack_id,
        )
        judgment = parse_judgment(completion.content)

        return ReplayResult(
            verdict=VerdictLabel(judgment.verdict.value),
            evidence=judgment.evidence[:1000],
            target_status_code=response.status_code,
            target_unavailable=False,
        )

    return _replay
