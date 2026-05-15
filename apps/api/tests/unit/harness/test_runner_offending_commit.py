"""Slice 6 DoD #3: regression_runs.offending_commit_hash population.

When a vulnerability replay aggregates to REGRESSED, the harness runner
must record the commit_hash of the current target_version on the new
regression_runs row. When the outcome is anything else, the field stays
NULL — only true regressions get attributed to a commit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.domain.regression_run import RegressionOutcome
from src.domain.target_version import TargetVersion
from src.domain.verdict import VerdictLabel
from src.domain.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from src.harness.runner import ReplayInput, ReplayResult, run_regressions


@dataclass
class _FakeAttackRow:
    """Stand-in for a SQLAlchemy row tuple."""

    attack_input: str

    def __getitem__(self, idx: int) -> str:
        if idx == 0:
            return self.attack_input
        raise IndexError(idx)


def _make_vuln(*, status: VulnerabilityStatus = VulnerabilityStatus.PATCHED) -> Vulnerability:
    return Vulnerability(
        id=uuid4(),
        vuln_id="VUL-0001",
        attack_id=uuid4(),
        verdict_id=uuid4(),
        severity=VulnerabilitySeverity.HIGH,
        title="t",
        clinical_impact="i",
        reproduction_steps="r",
        observed_behavior="o",
        expected_behavior="e",
        recommended_remediation="rr",
        status=status,
        owasp_llm_id="LLM01",
        mitre_atlas_technique_id="AML.T0051",
        hipaa_safeguard="164.312(a)",
        framework_versions={},
        target_version_id=None,
        rubric_snapshot=None,
        created_at=datetime.now(UTC),
        version_id=1,
    )


def _make_target_version(commit_hash: str | None) -> TargetVersion:
    return TargetVersion(
        id=uuid4(),
        target_manifest_id=uuid4(),
        target_id="openemr",
        version="v1.0.0",
        commit_hash=commit_hash,
        deployed_at=datetime.now(UTC),
        triggered_by="github_merge",
    )


@pytest.mark.asyncio
async def test_regressed_outcome_records_offending_commit_hash() -> None:
    """A regressed replay records the target_version's commit_hash."""
    vuln = _make_vuln()
    tv = _make_target_version(commit_hash="abc1234567890")

    session = AsyncMock()
    # Two separate session.execute results: vuln id list, then attack lookup.
    id_result = MagicMock()
    id_result.mappings.return_value.all.return_value = [{"id": vuln.id}]
    attack_result = MagicMock()
    attack_result.first.return_value = _FakeAttackRow("payload")
    session.execute = AsyncMock(side_effect=[id_result, attack_result])

    captured: dict[str, Any] = {}

    async def fake_replay(_inp: ReplayInput) -> ReplayResult:
        return ReplayResult(
            verdict=VerdictLabel.EXPLOIT,
            evidence="leaked",
            target_status_code=200,
        )

    async def fake_create(**kwargs: Any) -> None:
        captured.update(kwargs)

    with (
        patch(
            "src.harness.runner.VulnerabilityRepository.get_by_id",
            new=AsyncMock(return_value=vuln),
        ),
        patch(
            "src.harness.runner.VulnerabilityRepository.update_status",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "src.harness.runner.RegressionRunRepository.create",
            new=AsyncMock(side_effect=lambda _s, **kw: captured.update(kw)),
        ),
        patch(
            "src.harness.runner.TargetVersionRepository.get_by_id",
            new=AsyncMock(return_value=tv),
        ),
    ):
        await run_regressions(
            session=session,
            target_version_id=tv.id,
            replay_count=3,
            replay_fn=fake_replay,
            triggered_by="github_merge",
        )

    assert captured["outcome"] is RegressionOutcome.REGRESSED
    assert captured["offending_commit_hash"] == "abc1234567890"


@pytest.mark.asyncio
async def test_fix_verified_outcome_omits_offending_commit_hash() -> None:
    """A non-regressed outcome must leave offending_commit_hash as None."""
    vuln = _make_vuln()
    tv = _make_target_version(commit_hash="abc1234567890")

    session = AsyncMock()
    id_result = MagicMock()
    id_result.mappings.return_value.all.return_value = [{"id": vuln.id}]
    attack_result = MagicMock()
    attack_result.first.return_value = _FakeAttackRow("payload")
    session.execute = AsyncMock(side_effect=[id_result, attack_result])

    captured: dict[str, Any] = {}

    async def fake_replay(_inp: ReplayInput) -> ReplayResult:
        return ReplayResult(
            verdict=VerdictLabel.SAFE,
            evidence="blocked",
            target_status_code=200,
        )

    with (
        patch(
            "src.harness.runner.VulnerabilityRepository.get_by_id",
            new=AsyncMock(return_value=vuln),
        ),
        patch(
            "src.harness.runner.VulnerabilityRepository.update_status",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "src.harness.runner.RegressionRunRepository.create",
            new=AsyncMock(side_effect=lambda _s, **kw: captured.update(kw)),
        ),
        patch(
            "src.harness.runner.TargetVersionRepository.get_by_id",
            new=AsyncMock(return_value=tv),
        ),
    ):
        await run_regressions(
            session=session,
            target_version_id=tv.id,
            replay_count=3,
            replay_fn=fake_replay,
            triggered_by="github_merge",
        )

    assert captured["outcome"] is RegressionOutcome.FIX_VERIFIED
    assert captured["offending_commit_hash"] is None
