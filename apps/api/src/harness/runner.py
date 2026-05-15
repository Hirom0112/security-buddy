"""Top-level regression harness orchestration.

Given a target_version_id and a replay callable, the harness:
  1. Loads every vulnerability whose status is one we want to retest:
     proposed_fix, patched, regressed, unstable. (open/draft are
     untriaged or pre-fix and not part of the regression sweep.)
  2. For each vulnerability, replays the source attack N times via the
     injected callable.
  3. Aggregates the per-replay verdicts into a RegressionOutcome.
  4. Writes one regression_runs row per vulnerability.
  5. Transitions vulnerabilities.status based on the outcome.

The replay callable is injected so this module is testable without a
real target or LLM. The worker layer wires the real (TargetClient → Judge)
pipeline in. See workers/harness_worker.py.

Cross-category regression check (PLAN.md Slice 6 DoD):
  We replay EVERY vulnerability whose status was previously verified as
  fixed (status in {patched, proposed_fix}), not just the one tied to
  the merged PR. A regression elsewhere is just as important — possibly
  more so — than a regression on the freshly-fixed vuln.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import sqlalchemy as sa

from src.domain.regression_run import RegressionOutcome
from src.domain.verdict import VerdictLabel  # noqa: TC001
from src.harness.aggregate import aggregate_replays, next_vulnerability_status
from src.observability.events import log_event
from src.repositories.regression_runs import RegressionRunRepository
from src.repositories.target_versions import TargetVersionRepository
from src.repositories.vulnerabilities import VulnerabilityRepository

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.domain.vulnerability import Vulnerability


# Statuses that we re-test on every regression sweep. open/draft are not
# fixed yet, so re-running them has no information value.
_REGRESSION_TARGETS = (
    "proposed_fix",
    "patched",
    "regressed",
    "unstable",
)


@dataclass(frozen=True)
class ReplayInput:
    """Input passed to the replay callable for one replay attempt."""

    vulnerability_id: UUID
    attack_id: UUID
    attack_input: str
    rubric_snapshot: dict[str, object] | None


@dataclass(frozen=True)
class ReplayResult:
    """Output of one replay attempt."""

    verdict: VerdictLabel
    evidence: str
    target_status_code: int | None
    target_unavailable: bool = False


ReplayCallable = Callable[[ReplayInput], Awaitable[ReplayResult]]


@dataclass(frozen=True)
class RegressionSummary:
    """Returned by run_regressions — what the worker reports back."""

    target_version_id: UUID
    swept_count: int
    fix_verified_count: int
    regressed_count: int
    unstable_count: int
    target_unavailable_count: int


async def run_regressions(
    *,
    session: AsyncSession,
    target_version_id: UUID,
    replay_count: int,
    replay_fn: ReplayCallable,
    triggered_by: str,
) -> RegressionSummary:
    """Replay every confirmed-fix vulnerability against the new target version."""
    if replay_count <= 0:
        raise ValueError("replay_count must be positive")

    targets = await _load_regression_targets(session)

    vuln_repo = VulnerabilityRepository()
    run_repo = RegressionRunRepository()

    # Look up the commit_hash for the current target_version once. We
    # only attach it to regression_runs rows whose outcome is REGRESSED
    # — see DoD #3, Slice 6.
    current_version = await TargetVersionRepository().get_by_id(session, target_version_id)
    current_commit_hash = current_version.commit_hash if current_version is not None else None

    counts = {
        RegressionOutcome.FIX_VERIFIED: 0,
        RegressionOutcome.REGRESSED: 0,
        RegressionOutcome.UNSTABLE: 0,
        RegressionOutcome.TARGET_UNAVAILABLE: 0,
    }

    for vuln in targets:
        # 1. Locate the source attack via verdict_id → attack_id
        attack_input = await _get_attack_input(session, vuln.attack_id)
        if attack_input is None:
            log_event(
                "harness_skip_missing_attack",
                vulnerability_id=str(vuln.id),
                attack_id=str(vuln.attack_id),
                outcome="skipped",
            )
            continue

        # 2. Replay N times via the injected callable.
        verdicts: list[VerdictLabel] = []
        verdict_rows: list[dict[str, object]] = []
        for _ in range(replay_count):
            inp = ReplayInput(
                vulnerability_id=vuln.id,
                attack_id=vuln.attack_id,
                attack_input=attack_input,
                rubric_snapshot=vuln.rubric_snapshot,
            )
            result = await replay_fn(inp)
            if result.target_unavailable:
                # One unreachable replay aborts the whole vulnerability
                # — we don't want partial samples deciding fixed/regressed.
                verdicts = []
                verdict_rows = [
                    {
                        "verdict": "target_unavailable",
                        "evidence": result.evidence,
                        "target_status_code": result.target_status_code,
                    }
                ]
                break
            verdicts.append(result.verdict)
            verdict_rows.append(
                {
                    "verdict": result.verdict.value,
                    "evidence": result.evidence,
                    "target_status_code": result.target_status_code,
                }
            )

        # 3. Aggregate + persist.
        outcome = aggregate_replays(verdicts)
        counts[outcome] += 1

        offending = current_commit_hash if outcome is RegressionOutcome.REGRESSED else None
        await run_repo.create(
            session,
            vulnerability_id=vuln.id,
            target_version_id=target_version_id,
            replay_count=max(len(verdict_rows), 1),
            verdicts=verdict_rows,
            outcome=outcome,
            triggered_by=triggered_by,
            offending_commit_hash=offending,
        )

        new_status = next_vulnerability_status(outcome=outcome, prior_status=vuln.status)
        if new_status is not vuln.status:
            await vuln_repo.update_status(
                session,
                vulnerability_id=vuln.id,
                new_status=new_status,
            )

        log_event(
            "harness_replay_finished",
            vulnerability_id=str(vuln.id),
            outcome=outcome.value,
            prior_status=vuln.status.value,
            new_status=new_status.value,
        )

    return RegressionSummary(
        target_version_id=target_version_id,
        swept_count=len(targets),
        fix_verified_count=counts[RegressionOutcome.FIX_VERIFIED],
        regressed_count=counts[RegressionOutcome.REGRESSED],
        unstable_count=counts[RegressionOutcome.UNSTABLE],
        target_unavailable_count=counts[RegressionOutcome.TARGET_UNAVAILABLE],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_regression_targets(session: AsyncSession) -> list[Vulnerability]:
    """Return vulnerabilities whose status is part of the regression sweep."""
    repo = VulnerabilityRepository()
    placeholders = ",".join(f":s{i}" for i in range(len(_REGRESSION_TARGETS)))
    params = {f"s{i}": s for i, s in enumerate(_REGRESSION_TARGETS)}
    result = await session.execute(
        sa.text(
            "SELECT id FROM vulnerabilities"  # noqa: S608
            f" WHERE status IN ({placeholders})"
            " ORDER BY created_at ASC"
        ),
        params,
    )
    ids = [row["id"] for row in result.mappings().all()]
    out: list[Vulnerability] = []
    for vuln_id in ids:
        vuln = await repo.get_by_id(session, vuln_id)
        if vuln is not None:
            out.append(vuln)
    return out


async def _get_attack_input(session: AsyncSession, attack_id: UUID) -> str | None:
    """Read attacks.attack_input by id."""
    result = await session.execute(
        sa.text("SELECT attack_input FROM attacks WHERE id = :id"),
        {"id": str(attack_id)},
    )
    row = result.first()
    return str(row[0]) if row is not None else None
