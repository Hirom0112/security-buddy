"""Unit tests for run_single_vulnerability (operator rerun handler).

Covers the SAFE → PATCHED and EXPLOIT → REGRESSED transitions plus the
regression_runs row write. The single-replay path doesn't have to defend
against partial-sample voting — count=1 always maps directly to the
verdict's RegressionOutcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.domain.regression_run import RegressionOutcome, RegressionRun
from src.domain.target_version import TargetVersion
from src.domain.verdict import VerdictLabel
from src.domain.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from src.harness.runner import ReplayInput, ReplayResult, run_single_vulnerability


@dataclass
class _FakeAttackRow:
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


def _make_target_version() -> TargetVersion:
    return TargetVersion(
        id=uuid4(),
        target_manifest_id=uuid4(),
        target_id="openemr",
        version="operator_rerun",
        commit_hash="deadbeef",
        deployed_at=datetime.now(UTC),
        triggered_by="operator_rerun",
    )


def _make_run_row(vuln_id: Any, tv_id: Any, outcome: RegressionOutcome) -> RegressionRun:
    return RegressionRun(
        id=uuid4(),
        vulnerability_id=vuln_id,
        target_version_id=tv_id,
        replay_count=1,
        verdicts=[],
        outcome=outcome,
        triggered_by="operator_rerun:x",
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        offending_commit_hash=None,
    )


@pytest.mark.asyncio
async def test_rerun_safe_writes_row_and_flips_to_patched() -> None:
    """A single SAFE replay → FIX_VERIFIED → vulnerabilities.status = PATCHED."""
    vuln = _make_vuln(status=VulnerabilityStatus.REGRESSED)
    tv = _make_target_version()

    session = AsyncMock()
    attack_result = MagicMock()
    attack_result.first.return_value = _FakeAttackRow("payload")
    session.execute = AsyncMock(side_effect=[attack_result])

    async def fake_replay(_inp: ReplayInput) -> ReplayResult:
        return ReplayResult(verdict=VerdictLabel.SAFE, evidence="ok", target_status_code=200)

    create_mock = AsyncMock(
        return_value=_make_run_row(vuln.id, tv.id, RegressionOutcome.FIX_VERIFIED)
    )
    update_mock = AsyncMock(return_value=None)

    with (
        patch(
            "src.harness.runner.VulnerabilityRepository.get_by_id",
            new=AsyncMock(return_value=vuln),
        ),
        patch(
            "src.harness.runner.VulnerabilityRepository.update_status",
            new=update_mock,
        ),
        patch(
            "src.harness.runner.RegressionRunRepository.create",
            new=create_mock,
        ),
        patch(
            "src.harness.runner.TargetVersionRepository.get_by_id",
            new=AsyncMock(return_value=tv),
        ),
    ):
        result = await run_single_vulnerability(
            session=session,
            vulnerability_id=vuln.id,
            target_version_id=tv.id,
            replay_count=1,
            replay_fn=fake_replay,
            triggered_by=f"operator_rerun:{vuln.id}",
        )

    assert result.outcome is RegressionOutcome.FIX_VERIFIED
    assert result.new_status == VulnerabilityStatus.PATCHED.value
    create_mock.assert_called_once()
    update_kwargs = update_mock.call_args.kwargs
    assert update_kwargs["new_status"] is VulnerabilityStatus.PATCHED


@pytest.mark.asyncio
async def test_rerun_exploit_flips_to_regressed() -> None:
    """A single EXPLOIT replay → REGRESSED → status = REGRESSED."""
    vuln = _make_vuln(status=VulnerabilityStatus.PATCHED)
    tv = _make_target_version()

    session = AsyncMock()
    attack_result = MagicMock()
    attack_result.first.return_value = _FakeAttackRow("payload")
    session.execute = AsyncMock(side_effect=[attack_result])

    async def fake_replay(_inp: ReplayInput) -> ReplayResult:
        return ReplayResult(verdict=VerdictLabel.EXPLOIT, evidence="leak", target_status_code=200)

    create_mock = AsyncMock(return_value=_make_run_row(vuln.id, tv.id, RegressionOutcome.REGRESSED))
    update_mock = AsyncMock(return_value=None)

    with (
        patch(
            "src.harness.runner.VulnerabilityRepository.get_by_id",
            new=AsyncMock(return_value=vuln),
        ),
        patch(
            "src.harness.runner.VulnerabilityRepository.update_status",
            new=update_mock,
        ),
        patch(
            "src.harness.runner.RegressionRunRepository.create",
            new=create_mock,
        ),
        patch(
            "src.harness.runner.TargetVersionRepository.get_by_id",
            new=AsyncMock(return_value=tv),
        ),
    ):
        result = await run_single_vulnerability(
            session=session,
            vulnerability_id=vuln.id,
            target_version_id=tv.id,
            replay_count=1,
            replay_fn=fake_replay,
            triggered_by=f"operator_rerun:{vuln.id}",
        )

    assert result.outcome is RegressionOutcome.REGRESSED
    assert result.new_status == VulnerabilityStatus.REGRESSED.value
    # offending_commit_hash propagated from current target_version.
    create_kwargs = create_mock.call_args.kwargs
    assert create_kwargs["offending_commit_hash"] == "deadbeef"
    update_mock.assert_called_once()
