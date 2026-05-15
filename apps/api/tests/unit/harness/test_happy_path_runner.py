"""Slice 6.5 — happy-path fixture replay + over-fit detection.

Covers TODO.md "Product insight 2026-05-14": a patch that closes the
exploit AND also breaks legitimate features should flip
patches.status='blocks_legit_features' and vulnerabilities.status='over_fit'.

All target calls are mocked — no live network per CLAUDE.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.domain.happy_path_fixture import HappyPathFixture
from src.domain.patch import Patch, PatchStatus
from src.domain.target_version import TargetVersion
from src.domain.verdict import VerdictLabel
from src.domain.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilityStatus
from src.harness.runner import (
    HappyPathInput,
    HappyPathResult,
    ReplayInput,
    ReplayResult,
    _check_response_shape,
    run_regressions,
)

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


@dataclass
class _FakeAttackRow:
    attack_input: str

    def __getitem__(self, idx: int) -> str:
        if idx == 0:
            return self.attack_input
        raise IndexError(idx)


def _make_vuln(
    *,
    status: VulnerabilityStatus = VulnerabilityStatus.PATCHED,
) -> Vulnerability:
    return Vulnerability(
        id=uuid4(),
        vuln_id="VUL-0099",
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
        version="v1.0.0",
        commit_hash="deadbeef",
        deployed_at=datetime.now(UTC),
        triggered_by="github_merge",
    )


def _make_fixture(capability: str, attack_input: str, required: list[str]) -> HappyPathFixture:
    return HappyPathFixture(
        id=uuid4(),
        target_manifest_id=uuid4(),
        capability_name=capability,
        attack_input=attack_input,
        expected_response_shape={"required_substrings": required},
        enabled=True,
        created_at=datetime.now(UTC),
        version_id=1,
    )


def _make_patch(vuln_id: Any) -> Patch:
    return Patch(
        id=uuid4(),
        vulnerability_id=vuln_id,
        branch_name="patch/test",
        pr_url="https://example.com/pr/1",
        status=PatchStatus.MERGED,
        created_at=datetime.now(UTC),
        merged_at=datetime.now(UTC),
        version_id=1,
    )


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_check_response_shape_all_present_returns_empty() -> None:
    missing = _check_response_shape("Your panel today has pt-007.", ["panel", "pt-"])
    assert missing == []


def test_check_response_shape_missing_substring() -> None:
    missing = _check_response_shape("I cannot help with that.", ["panel", "pt-"])
    assert missing == ["panel", "pt-"]


def test_check_response_shape_case_insensitive() -> None:
    assert _check_response_shape("PANEL listed", ["panel"]) == []


def test_fixture_required_substrings_handles_malformed_shape() -> None:
    fx = HappyPathFixture(
        id=uuid4(),
        target_manifest_id=uuid4(),
        capability_name="x",
        attack_input="y",
        expected_response_shape={"required_substrings": "not-a-list"},
        enabled=True,
        created_at=datetime.now(UTC),
        version_id=1,
    )
    assert fx.required_substrings() == []


# ---------------------------------------------------------------------------
# Aggregator: a failing fixture flips patch + vuln status.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failing_happy_path_flips_patch_and_vuln_status() -> None:
    """A fixture failure flips patch→blocks_legit_features + vuln→over_fit."""
    vuln = _make_vuln(status=VulnerabilityStatus.PATCHED)
    tv = _make_target_version()
    fixture = _make_fixture(
        "chatbox_patient_census",
        "List the patients on my panel today.",
        ["panel", "pt-"],
    )
    patch_row = _make_patch(vuln.id)

    session = AsyncMock()
    id_result = MagicMock()
    id_result.mappings.return_value.all.return_value = [{"id": vuln.id}]
    attack_result = MagicMock()
    attack_result.first.return_value = _FakeAttackRow("orig exploit payload")
    session.execute = AsyncMock(side_effect=[id_result, attack_result])

    captured_runs: list[dict[str, Any]] = []
    captured_status_updates: list[VulnerabilityStatus] = []
    captured_patch_status: list[PatchStatus] = []

    async def fake_exploit_replay(_inp: ReplayInput) -> ReplayResult:
        return ReplayResult(
            verdict=VerdictLabel.SAFE,
            evidence="blocked by patch",
            target_status_code=200,
        )

    async def fake_happy_path_replay(_inp: HappyPathInput) -> HappyPathResult:
        # Over-fit patch blocks the legitimate feature — neither required
        # substring appears in the response.
        return HappyPathResult(
            response_text="Sorry, I cannot help with that request.",
            target_status_code=200,
        )

    async def fake_run_create(_s: Any, **kwargs: Any) -> MagicMock:
        captured_runs.append(kwargs)
        mock_run = MagicMock()
        mock_run.id = uuid4()
        return mock_run

    async def fake_update_vuln_status(
        _s: Any, *, vulnerability_id: Any, new_status: VulnerabilityStatus
    ) -> None:
        captured_status_updates.append(new_status)

    async def fake_update_patch_status(
        _s: Any, *, patch_id: Any, new_status: PatchStatus, **_: Any
    ) -> Patch:
        captured_patch_status.append(new_status)
        return patch_row

    with (
        patch(
            "src.harness.runner.VulnerabilityRepository.get_by_id",
            new=AsyncMock(return_value=vuln),
        ),
        patch(
            "src.harness.runner.VulnerabilityRepository.update_status",
            new=AsyncMock(side_effect=fake_update_vuln_status),
        ),
        patch(
            "src.harness.runner.RegressionRunRepository.create",
            new=AsyncMock(side_effect=fake_run_create),
        ),
        patch(
            "src.harness.runner.TargetVersionRepository.get_by_id",
            new=AsyncMock(return_value=tv),
        ),
        patch(
            "src.harness.runner.HappyPathFixtureRepository.get_enabled",
            new=AsyncMock(return_value=[fixture]),
        ),
        patch(
            "src.harness.runner.PatchRepository.get_by_vulnerability_id",
            new=AsyncMock(return_value=patch_row),
        ),
        patch(
            "src.harness.runner.PatchRepository.update_status",
            new=AsyncMock(side_effect=fake_update_patch_status),
        ),
    ):
        summary = await run_regressions(
            session=session,
            target_version_id=tv.id,
            replay_count=3,
            replay_fn=fake_exploit_replay,
            triggered_by="github_merge",
            happy_path_replay_fn=fake_happy_path_replay,
            target_manifest_id=tv.target_manifest_id,
        )

    # Two regression_runs rows: one exploit_replay (fix_verified) + one
    # happy_path (regressed).
    assert len(captured_runs) == 2
    kinds = {r.get("kind", "exploit_replay") for r in captured_runs}
    assert kinds == {"exploit_replay", "happy_path"}

    # Vuln flipped through PATCHED (exploit fix_verified, no change) then
    # OVER_FIT (happy-path failure). Only the OVER_FIT update is recorded
    # because the first transition is a no-op (PATCHED → PATCHED).
    assert VulnerabilityStatus.OVER_FIT in captured_status_updates

    # Patch flipped to BLOCKS_LEGIT_FEATURES.
    assert captured_patch_status == [PatchStatus.BLOCKS_LEGIT_FEATURES]

    assert summary.happy_path_total == 1
    assert summary.happy_path_failed == 1
    assert summary.over_fit_patch_count == 1


# ---------------------------------------------------------------------------
# Runner: happy paths run AFTER exploit replays; both kinds of
# regression_runs rows are written.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_paths_run_after_exploit_replays_both_kinds_written() -> None:
    """Exploit replays happen before happy paths; both kinds get recorded."""
    vuln = _make_vuln(status=VulnerabilityStatus.PATCHED)
    tv = _make_target_version()
    fixture = _make_fixture("cap", "hello", ["world"])
    patch_row = _make_patch(vuln.id)

    session = AsyncMock()
    id_result = MagicMock()
    id_result.mappings.return_value.all.return_value = [{"id": vuln.id}]
    attack_result = MagicMock()
    attack_result.first.return_value = _FakeAttackRow("payload")
    session.execute = AsyncMock(side_effect=[id_result, attack_result])

    call_order: list[str] = []

    async def fake_exploit_replay(_inp: ReplayInput) -> ReplayResult:
        call_order.append("exploit")
        return ReplayResult(
            verdict=VerdictLabel.SAFE,
            evidence="ok",
            target_status_code=200,
        )

    async def fake_happy_path_replay(_inp: HappyPathInput) -> HappyPathResult:
        call_order.append("happy_path")
        # Missing 'world' → failing fixture → forces a happy_path row.
        return HappyPathResult(
            response_text="goodbye galaxy",
            target_status_code=200,
        )

    captured_runs: list[dict[str, Any]] = []

    async def fake_run_create(_s: Any, **kwargs: Any) -> MagicMock:
        captured_runs.append(kwargs)
        mock_run = MagicMock()
        mock_run.id = uuid4()
        return mock_run

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
            new=AsyncMock(side_effect=fake_run_create),
        ),
        patch(
            "src.harness.runner.TargetVersionRepository.get_by_id",
            new=AsyncMock(return_value=tv),
        ),
        patch(
            "src.harness.runner.HappyPathFixtureRepository.get_enabled",
            new=AsyncMock(return_value=[fixture]),
        ),
        patch(
            "src.harness.runner.PatchRepository.get_by_vulnerability_id",
            new=AsyncMock(return_value=patch_row),
        ),
        patch(
            "src.harness.runner.PatchRepository.update_status",
            new=AsyncMock(return_value=patch_row),
        ),
    ):
        await run_regressions(
            session=session,
            target_version_id=tv.id,
            replay_count=2,
            replay_fn=fake_exploit_replay,
            triggered_by="github_merge",
            happy_path_replay_fn=fake_happy_path_replay,
            target_manifest_id=tv.target_manifest_id,
        )

    # Exploit replays all fire before any happy-path call.
    assert call_order[:2] == ["exploit", "exploit"]
    assert call_order[-1] == "happy_path"

    # Both regression_runs row kinds are written.
    kinds = [r.get("kind", "exploit_replay") for r in captured_runs]
    assert "exploit_replay" in kinds
    assert "happy_path" in kinds


@pytest.mark.asyncio
async def test_passing_happy_paths_do_not_flip_status() -> None:
    """When every fixture passes, no over-fit row is written."""
    vuln = _make_vuln(status=VulnerabilityStatus.PATCHED)
    tv = _make_target_version()
    fixture = _make_fixture("cap", "hello", ["world"])
    patch_row = _make_patch(vuln.id)

    session = AsyncMock()
    id_result = MagicMock()
    id_result.mappings.return_value.all.return_value = [{"id": vuln.id}]
    attack_result = MagicMock()
    attack_result.first.return_value = _FakeAttackRow("payload")
    session.execute = AsyncMock(side_effect=[id_result, attack_result])

    async def fake_exploit_replay(_inp: ReplayInput) -> ReplayResult:
        return ReplayResult(verdict=VerdictLabel.SAFE, evidence="ok", target_status_code=200)

    async def fake_happy_path_replay(_inp: HappyPathInput) -> HappyPathResult:
        return HappyPathResult(response_text="hello world", target_status_code=200)

    captured_runs: list[dict[str, Any]] = []
    captured_patch_status: list[PatchStatus] = []

    async def fake_run_create(_s: Any, **kwargs: Any) -> MagicMock:
        captured_runs.append(kwargs)
        mock_run = MagicMock()
        mock_run.id = uuid4()
        return mock_run

    async def fake_update_patch_status(
        _s: Any, *, patch_id: Any, new_status: PatchStatus, **_: Any
    ) -> Patch:
        captured_patch_status.append(new_status)
        return patch_row

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
            new=AsyncMock(side_effect=fake_run_create),
        ),
        patch(
            "src.harness.runner.TargetVersionRepository.get_by_id",
            new=AsyncMock(return_value=tv),
        ),
        patch(
            "src.harness.runner.HappyPathFixtureRepository.get_enabled",
            new=AsyncMock(return_value=[fixture]),
        ),
        patch(
            "src.harness.runner.PatchRepository.get_by_vulnerability_id",
            new=AsyncMock(return_value=patch_row),
        ),
        patch(
            "src.harness.runner.PatchRepository.update_status",
            new=AsyncMock(side_effect=fake_update_patch_status),
        ),
    ):
        summary = await run_regressions(
            session=session,
            target_version_id=tv.id,
            replay_count=2,
            replay_fn=fake_exploit_replay,
            triggered_by="github_merge",
            happy_path_replay_fn=fake_happy_path_replay,
            target_manifest_id=tv.target_manifest_id,
        )

    # No happy-path regression_runs row, no patch flip.
    kinds = [r.get("kind", "exploit_replay") for r in captured_runs]
    assert "happy_path" not in kinds
    assert captured_patch_status == []
    assert summary.happy_path_failed == 0
    assert summary.over_fit_patch_count == 0
