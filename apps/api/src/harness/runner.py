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

from src.domain.patch import PatchStatus
from src.domain.regression_run import RegressionOutcome
from src.domain.verdict import VerdictLabel  # noqa: TC001
from src.domain.vulnerability import VulnerabilityStatus
from src.harness.aggregate import aggregate_replays, next_vulnerability_status
from src.observability.events import log_event
from src.repositories.happy_path_fixtures import HappyPathFixtureRepository
from src.repositories.patches import PatchRepository
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
class HappyPathInput:
    """Input passed to a happy-path replay callable."""

    fixture_id: UUID
    capability_name: str
    attack_input: str


@dataclass(frozen=True)
class HappyPathResult:
    """Output of one happy-path replay attempt."""

    response_text: str
    target_status_code: int | None
    target_unavailable: bool = False


HappyPathReplayCallable = Callable[[HappyPathInput], Awaitable[HappyPathResult]]


@dataclass(frozen=True)
class HappyPathOutcome:
    """One fixture's pass/fail result, captured for the worker + UI."""

    fixture_id: UUID
    capability_name: str
    passed: bool
    response_text: str
    target_status_code: int | None
    missing_substrings: list[str]
    target_unavailable: bool = False


def _check_response_shape(response_text: str, required_substrings: list[str]) -> list[str]:
    """Return the list of substrings that did NOT appear in the response.

    An empty return list means the fixture passed. Substring match is
    case-insensitive — intentionally generous so cosmetic differences
    don't trip false positives.
    """
    lowered = response_text.lower()
    return [s for s in required_substrings if s.lower() not in lowered]


@dataclass(frozen=True)
class SingleRerunResult:
    """Returned by run_single_vulnerability — what the worker reports back."""

    vulnerability_id: UUID
    regression_run_id: UUID | None
    outcome: RegressionOutcome
    prior_status: str
    new_status: str


@dataclass(frozen=True)
class RegressionSummary:
    """Returned by run_regressions — what the worker reports back."""

    target_version_id: UUID
    swept_count: int
    fix_verified_count: int
    regressed_count: int
    unstable_count: int
    target_unavailable_count: int
    happy_path_total: int = 0
    happy_path_passed: int = 0
    happy_path_failed: int = 0
    over_fit_patch_count: int = 0


async def run_regressions(
    *,
    session: AsyncSession,
    target_version_id: UUID,
    replay_count: int,
    replay_fn: ReplayCallable,
    triggered_by: str,
    happy_path_replay_fn: HappyPathReplayCallable | None = None,
    target_manifest_id: UUID | None = None,
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

    # ------------------------------------------------------------------
    # Happy-path fixtures (Slice 6.5).
    # Additive: only runs when the caller passes a happy_path_replay_fn
    # AND a target_manifest_id. The historical exploit-replay loop above
    # is untouched. Each fixture failure flips the *currently-fixed*
    # vulnerabilities to over_fit + their merged patches to
    # blocks_legit_features.
    # ------------------------------------------------------------------
    hp_total = 0
    hp_passed = 0
    hp_failed = 0
    over_fit_patches = 0
    if happy_path_replay_fn is not None and target_manifest_id is not None:
        hp_outcomes = await _run_happy_paths(
            session=session,
            target_manifest_id=target_manifest_id,
            replay_fn=happy_path_replay_fn,
        )
        hp_total = len(hp_outcomes)
        hp_passed = sum(1 for o in hp_outcomes if o.passed)
        hp_failed = hp_total - hp_passed

        if hp_failed > 0 and targets:
            # We have failed legit-feature fixtures AND we have monitored
            # vulnerabilities — i.e. some patch may be over-fitting. Flip
            # status on every currently-PATCHED vuln + its merged patch.
            # We also record one regression_runs row of kind=happy_path
            # per failing fixture, attributed to the first patched vuln so
            # the row has a valid FK target. This is a lossy attribution
            # — a future migration can split off a dedicated table — but
            # it's enough to surface the signal in the UI today.
            over_fit_patches = await _flip_over_fit(
                session=session,
                target_version_id=target_version_id,
                triggered_by=triggered_by,
                failing_outcomes=[o for o in hp_outcomes if not o.passed],
                patched_vulns=[v for v in targets if v.status is VulnerabilityStatus.PATCHED],
                run_repo=run_repo,
                vuln_repo=vuln_repo,
            )

    return RegressionSummary(
        target_version_id=target_version_id,
        swept_count=len(targets),
        fix_verified_count=counts[RegressionOutcome.FIX_VERIFIED],
        regressed_count=counts[RegressionOutcome.REGRESSED],
        unstable_count=counts[RegressionOutcome.UNSTABLE],
        target_unavailable_count=counts[RegressionOutcome.TARGET_UNAVAILABLE],
        happy_path_total=hp_total,
        happy_path_passed=hp_passed,
        happy_path_failed=hp_failed,
        over_fit_patch_count=over_fit_patches,
    )


async def run_single_vulnerability(
    *,
    session: AsyncSession,
    vulnerability_id: UUID,
    target_version_id: UUID,
    replay_count: int,
    replay_fn: ReplayCallable,
    triggered_by: str,
) -> SingleRerunResult:
    """Replay a single vulnerability against the current target version.

    Mirror of run_regressions but scoped to one vuln. Used by the operator
    "Re-run this attack" button. Writes one regression_runs row, transitions
    the vulnerability's status the same way the sweep does.
    """
    if replay_count <= 0:
        raise ValueError("replay_count must be positive")

    vuln_repo = VulnerabilityRepository()
    run_repo = RegressionRunRepository()

    vuln = await vuln_repo.get_by_id(session, vulnerability_id)
    if vuln is None:
        raise ValueError(f"vulnerability {vulnerability_id} not found")

    current_version = await TargetVersionRepository().get_by_id(session, target_version_id)
    current_commit_hash = current_version.commit_hash if current_version is not None else None

    attack_input = await _get_attack_input(session, vuln.attack_id)
    if attack_input is None:
        log_event(
            "harness_rerun_skip_missing_attack",
            vulnerability_id=str(vuln.id),
            attack_id=str(vuln.attack_id),
            outcome="skipped",
        )
        return SingleRerunResult(
            vulnerability_id=vuln.id,
            regression_run_id=None,
            outcome=RegressionOutcome.TARGET_UNAVAILABLE,
            prior_status=vuln.status.value,
            new_status=vuln.status.value,
        )

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

    outcome = aggregate_replays(verdicts)
    offending = current_commit_hash if outcome is RegressionOutcome.REGRESSED else None
    run_row = await run_repo.create(
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
        "harness_rerun_finished",
        vulnerability_id=str(vuln.id),
        outcome=outcome.value,
        prior_status=vuln.status.value,
        new_status=new_status.value,
    )

    return SingleRerunResult(
        vulnerability_id=vuln.id,
        regression_run_id=run_row.id,
        outcome=outcome,
        prior_status=vuln.status.value,
        new_status=new_status.value,
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


async def _run_happy_paths(
    *,
    session: AsyncSession,
    target_manifest_id: UUID,
    replay_fn: HappyPathReplayCallable,
) -> list[HappyPathOutcome]:
    """Fire every enabled happy-path fixture once and record per-fixture pass/fail.

    Lo-fi substring match per fixture.expected_response_shape — see
    docstring on HappyPathFixture and CLAUDE.md / TODO "Product insight
    2026-05-14".
    """
    fixture_repo = HappyPathFixtureRepository()
    fixtures = await fixture_repo.get_enabled(session, target_manifest_id)
    outcomes: list[HappyPathOutcome] = []
    for fx in fixtures:
        inp = HappyPathInput(
            fixture_id=fx.id,
            capability_name=fx.capability_name,
            attack_input=fx.attack_input,
        )
        result = await replay_fn(inp)
        if result.target_unavailable:
            outcomes.append(
                HappyPathOutcome(
                    fixture_id=fx.id,
                    capability_name=fx.capability_name,
                    passed=False,
                    response_text=result.response_text,
                    target_status_code=result.target_status_code,
                    missing_substrings=fx.required_substrings(),
                    target_unavailable=True,
                )
            )
            log_event(
                "harness_happy_path_target_unavailable",
                fixture_id=str(fx.id),
                capability_name=fx.capability_name,
                outcome="failure",
            )
            continue
        missing = _check_response_shape(result.response_text, fx.required_substrings())
        passed = len(missing) == 0
        outcomes.append(
            HappyPathOutcome(
                fixture_id=fx.id,
                capability_name=fx.capability_name,
                passed=passed,
                response_text=result.response_text,
                target_status_code=result.target_status_code,
                missing_substrings=missing,
            )
        )
        log_event(
            "harness_happy_path_finished",
            fixture_id=str(fx.id),
            capability_name=fx.capability_name,
            outcome="success" if passed else "failure",
            missing_count=len(missing),
        )
    return outcomes


async def _flip_over_fit(
    *,
    session: AsyncSession,
    target_version_id: UUID,
    triggered_by: str,
    failing_outcomes: list[HappyPathOutcome],
    patched_vulns: list[Vulnerability],
    run_repo: RegressionRunRepository,
    vuln_repo: VulnerabilityRepository,
) -> int:
    """Record happy_path regression rows and flip statuses on over-fit.

    Returns the number of patches flipped to blocks_legit_features.
    """
    if not failing_outcomes or not patched_vulns:
        return 0

    # Build the verdicts payload once — same shape for every row we write so
    # the UI's tally code keeps working.
    verdict_rows: list[dict[str, object]] = [
        {
            "verdict": "happy_path_pass" if o.passed else "happy_path_fail",
            "evidence": (
                f"capability={o.capability_name}; "
                f"missing={','.join(o.missing_substrings) or 'none'}"
            ),
            "target_status_code": o.target_status_code,
            "capability_name": o.capability_name,
            "fixture_id": str(o.fixture_id),
        }
        for o in failing_outcomes
    ]

    patch_repo = PatchRepository()
    flipped_patches = 0
    for vuln in patched_vulns:
        await run_repo.create(
            session,
            vulnerability_id=vuln.id,
            target_version_id=target_version_id,
            replay_count=max(len(verdict_rows), 1),
            verdicts=verdict_rows,
            outcome=RegressionOutcome.REGRESSED,
            triggered_by=triggered_by,
            offending_commit_hash=None,
            kind="happy_path",
        )
        await vuln_repo.update_status(
            session,
            vulnerability_id=vuln.id,
            new_status=VulnerabilityStatus.OVER_FIT,
        )
        patch = await patch_repo.get_by_vulnerability_id(session, vuln.id)
        if patch is not None and patch.status is PatchStatus.MERGED:
            await patch_repo.update_status(
                session,
                patch_id=patch.id,
                new_status=PatchStatus.BLOCKS_LEGIT_FEATURES,
            )
            flipped_patches += 1
        log_event(
            "harness_over_fit_detected",
            vulnerability_id=str(vuln.id),
            prior_status=vuln.status.value,
            new_status=VulnerabilityStatus.OVER_FIT.value,
            failing_count=len(failing_outcomes),
        )
    return flipped_patches
