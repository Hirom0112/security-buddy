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
from src.agents.judge.schema import Rubric, TrustBoundary
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
        # 3. Judge the response.
        #    Slice 6 §1 / CLAUDE.md §6a: prefer the FROZEN rubric snapshot
        #    written by the documentation agent at confirmation time. This
        #    prevents a mid-incident manifest change from silently re-grading
        #    an old finding. Legacy rows without rubric_snapshot["full"] fall
        #    back to live resolution.
        # ----------------------------------------------------------
        rubric = _rubric_from_snapshot(
            snapshot=inp.rubric_snapshot,
            subcategory=attack.subcategory,
        )
        if rubric is None:
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


def _rubric_from_snapshot(
    *,
    snapshot: dict[str, object] | None,
    subcategory: str,
) -> Rubric | None:
    """Reconstruct a Rubric from vulnerabilities.rubric_snapshot["full"].

    Returns None for legacy snapshots that predate the frozen-rubric work
    (no "full" key), so the caller can fall back to live resolution. We
    return None — not raise — because a missing snapshot is a known
    backward-compat path, not a bug.
    """
    if not isinstance(snapshot, dict):
        return None
    full = snapshot.get("full")
    if not isinstance(full, dict):
        return None

    raw_boundaries = full.get("trust_boundaries", [])
    if not isinstance(raw_boundaries, list) or not raw_boundaries:
        return None
    try:
        boundaries = [TrustBoundary.model_validate(b) for b in raw_boundaries]
    except Exception:
        return None

    expected_safe: str | None = None
    raw_expected = full.get("expected_safe_behaviors", [])
    if isinstance(raw_expected, list):
        for entry in raw_expected:
            if not isinstance(entry, dict):
                continue
            if entry.get("subcategory") == subcategory:
                behavior = entry.get("expected_safe_behavior")
                if isinstance(behavior, str) and behavior.strip():
                    expected_safe = behavior
                    break
    if expected_safe is None:
        return None

    raw_criteria = full.get("success_criteria", [])
    # success_criteria in the snapshot is a list (one element per brief).
    # The judge schema expects a dict; collapse to the first entry, or {}.
    success_criteria: dict[str, object] = {}
    if isinstance(raw_criteria, list) and raw_criteria:
        first = raw_criteria[0]
        if isinstance(first, dict):
            success_criteria = first

    try:
        return Rubric(
            subcategory=subcategory,
            trust_boundaries=boundaries,
            expected_safe_behavior=expected_safe,
            success_criteria=success_criteria,
        )
    except Exception:
        return None
