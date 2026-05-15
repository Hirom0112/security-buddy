"""Unit tests for the `target_subcategory` pin override in `run_tick`.

Bug: `POST /api/v1/campaigns/start` accepts an optional `target_subcategory`
pin, but the Orchestrator's tick ignores the pinned value and re-picks via
`pick_top()`. These tests pin a (lower-priority) subcategory and assert it
wins over a strictly higher-priority alternative — locking the behaviour the
route's contract already promised.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from src.agents.orchestrator.schema import GeneratedBrief
from src.agents.orchestrator.tick import run_tick
from src.domain.campaign import (
    BriefStatus,
    Campaign,
    CampaignBrief,
    CampaignMode,
    CampaignStatus,
)
from src.domain.coverage import CoverageRow, TaxonomyPriority

_CAMPAIGN_ID = uuid4()
_BRIEF_ID = uuid4()
_TARGET_VERSION_ID = uuid4()

_PIN = "tool_misuse/unintended_invocation"
_PRIORITY_WINNER = "identity_role/privilege_escalation"


def _campaign(target_subcategory: str | None) -> Campaign:
    return Campaign(
        id=_CAMPAIGN_ID,
        status=CampaignStatus.PENDING,
        mode=CampaignMode.LIVE,
        budget_usd=Decimal("5.00"),
        target_version_id=_TARGET_VERSION_ID,
        target_subcategory=target_subcategory,
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        version_id=1,
    )


def _coverage_rows() -> list[CoverageRow]:
    # The "priority winner" outranks the pinned row deliberately: HIGH taxonomy
    # + open findings + staleness vs LOW taxonomy + nothing else. The pin must
    # still win when set.
    return [
        CoverageRow(
            category="identity_role",
            subcategory=_PRIORITY_WINNER,
            taxonomy_priority=TaxonomyPriority.CRITICAL,
            attempts=5,
            exploit_count=0,
            open_findings_count=2,
            days_since_last_attempted=14,
        ),
        CoverageRow(
            category="tool_misuse",
            subcategory=_PIN,
            taxonomy_priority=TaxonomyPriority.LOW,
            attempts=3,
            exploit_count=0,
            open_findings_count=0,
            days_since_last_attempted=1,
        ),
    ]


def _generated_brief() -> GeneratedBrief:
    return GeneratedBrief(
        description=(
            "Deterministic stub brief used in the run_tick pin test. Covers "
            "the minimum schema requirements with realistic-looking content."
        ),
        proposed_variant_count=8,
        proposed_budget_usd=Decimal("2.00"),
        success_criteria={"evidence_required": "Judge verdict 'exploit'"},
        rationale=("Stub rationale for unit test — real LLM call is patched out."),
    )


def _brief_row(subcategory: str) -> CampaignBrief:
    return CampaignBrief(
        id=_BRIEF_ID,
        campaign_id=_CAMPAIGN_ID,
        target_subcategory=subcategory,
        description="x" * 30,
        variant_count=8,
        success_criteria={"evidence_required": "Judge verdict 'exploit'"},
        budget_usd=Decimal("2.00"),
        status=BriefStatus.PENDING,
        created_at=datetime.now(UTC),
    )


class _Repos:
    """Bundle of AsyncMocks used to replace the four repos `run_tick` constructs."""

    def __init__(self, *, campaign: Campaign, rows: list[CoverageRow]) -> None:
        self.campaign_repo = MagicMock()
        self.campaign_repo.get = AsyncMock(return_value=campaign)
        self.campaign_repo.update_status = AsyncMock()
        self.campaign_repo.set_target_subcategory = AsyncMock()
        self.captured_add_brief_kwargs: dict[str, Any] = {}

        async def _add_brief(_session: Any, **kwargs: Any) -> CampaignBrief:
            self.captured_add_brief_kwargs = kwargs
            return _brief_row(kwargs["target_subcategory"])

        self.campaign_repo.add_brief = AsyncMock(side_effect=_add_brief)

        self.coverage_repo = MagicMock()
        self.coverage_repo.snapshot = AsyncMock(return_value=rows)

        self.manifest_repo = MagicMock()
        self.manifest_repo.get_active = AsyncMock(return_value=None)

        self.traces_repo = MagicMock()
        self.traces_repo.total_cost_for_campaign = AsyncMock(return_value=Decimal("0"))


def _install_repo_patches(monkeypatch: pytest.MonkeyPatch, repos: _Repos) -> None:
    import src.agents.orchestrator.tick as tick_mod

    monkeypatch.setattr(tick_mod, "CampaignRepository", lambda: repos.campaign_repo)
    monkeypatch.setattr(tick_mod, "CoverageRepository", lambda: repos.coverage_repo)
    monkeypatch.setattr(tick_mod, "TargetManifestRepository", lambda: repos.manifest_repo)
    monkeypatch.setattr(tick_mod, "AgentTracesRepository", lambda: repos.traces_repo)


@pytest.mark.asyncio
async def test_run_tick_honours_target_subcategory_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinned subcategory wins over the priority function's top pick.

    The Orchestrator must not silently re-pick when the operator pinned a
    target via POST /campaigns/start. The pin is the operator's intent and
    is authoritative.
    """
    rows = _coverage_rows()
    repos = _Repos(campaign=_campaign(target_subcategory=_PIN), rows=rows)
    _install_repo_patches(monkeypatch, repos)

    # Pin is in the (fake) taxonomy.
    async def _exists(_session: Any, sub: str) -> bool:
        return sub in {_PIN, _PRIORITY_WINNER}

    import src.agents.orchestrator.tick as tick_mod

    monkeypatch.setattr(tick_mod, "_subcategory_in_taxonomy", _exists, raising=False)

    # Patch the brief generator to a deterministic stub so we exercise tick logic
    # only — not the LLM path.
    async def _stub_generate_brief(**_kwargs: Any) -> tuple[GeneratedBrief, bool]:
        return _generated_brief(), False

    monkeypatch.setattr(tick_mod, "generate_brief", _stub_generate_brief)

    outcome = await run_tick(
        campaign_id=_CAMPAIGN_ID,
        session=MagicMock(),
        llm_client=MagicMock(),
    )

    assert outcome.chosen_subcategory == _PIN, (
        f"Pin '{_PIN}' must win, not the priority pick '{outcome.chosen_subcategory}'."
    )
    # The brief row also reflects the pin.
    assert repos.captured_add_brief_kwargs["target_subcategory"] == _PIN


@pytest.mark.asyncio
async def test_run_tick_invalid_pin_falls_back_to_priority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown pinned subcategory falls back to the priority function."""
    rows = _coverage_rows()
    repos = _Repos(
        campaign=_campaign(target_subcategory="bogus/not_in_taxonomy"),
        rows=rows,
    )
    _install_repo_patches(monkeypatch, repos)

    async def _exists(_session: Any, sub: str) -> bool:
        return sub in {_PIN, _PRIORITY_WINNER}  # bogus value not present

    import src.agents.orchestrator.tick as tick_mod

    monkeypatch.setattr(tick_mod, "_subcategory_in_taxonomy", _exists, raising=False)

    async def _stub_generate_brief(**_kwargs: Any) -> tuple[GeneratedBrief, bool]:
        return _generated_brief(), False

    monkeypatch.setattr(tick_mod, "generate_brief", _stub_generate_brief)

    outcome = await run_tick(
        campaign_id=_CAMPAIGN_ID,
        session=MagicMock(),
        llm_client=MagicMock(),
    )

    # Falls back to the priority winner.
    assert outcome.chosen_subcategory == _PRIORITY_WINNER
    assert repos.captured_add_brief_kwargs["target_subcategory"] == _PRIORITY_WINNER
