"""Unit tests for the auto-retry branch in the harness worker.

When run_regressions transitions a vulnerability to UNSTABLE or REGRESSED,
the worker looks up the vuln's active patch and either enqueues a retry
(`patch.retry_unstable`) or logs `patch_retry_exhausted` if attempt #2
has already landed bad.

Cap is 2 attempts total per vulnerability (attempt #1 = initial, attempt
#2 = first retry). See CLAUDE.md §"Auto-retry on unstable regression".
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from src.domain.patch import Patch, PatchStatus
from src.domain.regression_run import RegressionOutcome
from src.workers.harness_worker import process_unstable_retries


def _make_patch(*, vuln_id, attempt_number: int, status: PatchStatus) -> Patch:
    return Patch(
        id=uuid4(),
        vulnerability_id=vuln_id,
        branch_name=f"security-buddy/attempt-{attempt_number}",
        pr_url=f"https://github.com/x/y/pull/{attempt_number}",
        status=status,
        created_at=datetime.now(UTC),
        merged_at=None,
        version_id=1,
        attempt_number=attempt_number,
    )


@pytest.mark.asyncio
async def test_unstable_with_attempt_1_enqueues_retry() -> None:
    """attempt_number=1 + UNSTABLE → enqueue patch.retry_unstable, flip to SUPERSEDED."""
    vuln_id = uuid4()
    prior_patch = _make_patch(vuln_id=vuln_id, attempt_number=1, status=PatchStatus.MERGED)

    session = MagicMock()
    update_mock = AsyncMock(return_value=None)
    enqueue_mock = AsyncMock(return_value=None)

    with (
        patch(
            "src.workers.harness_worker.PatchRepository.get_by_vulnerability_id",
            new=AsyncMock(return_value=prior_patch),
        ),
        patch(
            "src.workers.harness_worker.PatchRepository.update_status",
            new=update_mock,
        ),
        patch(
            "src.workers.harness_worker.enqueue_patch_retry_unstable",
            new=enqueue_mock,
        ),
    ):
        await process_unstable_retries(
            session=session,
            flagged=[(vuln_id, RegressionOutcome.UNSTABLE)],
            request_id="req-1",
        )

    enqueue_mock.assert_awaited_once()
    call_args = enqueue_mock.await_args
    assert call_args.args[0] == vuln_id
    assert call_args.args[1] == "req-1"

    update_mock.assert_awaited_once()
    update_kwargs = update_mock.await_args.kwargs
    assert update_kwargs["patch_id"] == prior_patch.id
    assert update_kwargs["new_status"] is PatchStatus.SUPERSEDED


@pytest.mark.asyncio
async def test_regressed_with_attempt_1_enqueues_retry() -> None:
    """REGRESSED is treated the same as UNSTABLE for the retry decision."""
    vuln_id = uuid4()
    prior_patch = _make_patch(
        vuln_id=vuln_id, attempt_number=1, status=PatchStatus.AWAITING_HUMAN_REVIEW
    )

    enqueue_mock = AsyncMock(return_value=None)

    with (
        patch(
            "src.workers.harness_worker.PatchRepository.get_by_vulnerability_id",
            new=AsyncMock(return_value=prior_patch),
        ),
        patch(
            "src.workers.harness_worker.PatchRepository.update_status",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "src.workers.harness_worker.enqueue_patch_retry_unstable",
            new=enqueue_mock,
        ),
    ):
        await process_unstable_retries(
            session=MagicMock(),
            flagged=[(vuln_id, RegressionOutcome.REGRESSED)],
            request_id="req-2",
        )

    enqueue_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_unstable_with_attempt_2_does_not_enqueue() -> None:
    """attempt_number=2 + UNSTABLE → log patch_retry_exhausted, no enqueue."""
    vuln_id = uuid4()
    prior_patch = _make_patch(
        vuln_id=vuln_id, attempt_number=2, status=PatchStatus.AWAITING_HUMAN_REVIEW
    )

    enqueue_mock = AsyncMock(return_value=None)
    update_mock = AsyncMock(return_value=None)

    with (
        patch(
            "src.workers.harness_worker.PatchRepository.get_by_vulnerability_id",
            new=AsyncMock(return_value=prior_patch),
        ),
        patch(
            "src.workers.harness_worker.PatchRepository.update_status",
            new=update_mock,
        ),
        patch(
            "src.workers.harness_worker.enqueue_patch_retry_unstable",
            new=enqueue_mock,
        ),
        patch("src.workers.harness_worker.log_event") as log_mock,
    ):
        await process_unstable_retries(
            session=MagicMock(),
            flagged=[(vuln_id, RegressionOutcome.UNSTABLE)],
            request_id="req-3",
        )

    enqueue_mock.assert_not_awaited()
    update_mock.assert_not_awaited()

    # log_event was called with patch_retry_exhausted exactly once.
    exhausted_calls = [
        c for c in log_mock.call_args_list if c.args and c.args[0] == "patch_retry_exhausted"
    ]
    assert len(exhausted_calls) == 1
    kwargs = exhausted_calls[0].kwargs
    assert kwargs["vulnerability_id"] == str(vuln_id)
    assert kwargs["attempt_number"] == 2
    assert kwargs["outcome"] == "unstable"


@pytest.mark.asyncio
async def test_no_active_patch_skips_retry() -> None:
    """If we can't find an active patch for the vuln, no retry, no crash."""
    vuln_id = uuid4()
    enqueue_mock = AsyncMock(return_value=None)
    with (
        patch(
            "src.workers.harness_worker.PatchRepository.get_by_vulnerability_id",
            new=AsyncMock(return_value=None),
        ),
        patch(
            "src.workers.harness_worker.enqueue_patch_retry_unstable",
            new=enqueue_mock,
        ),
    ):
        await process_unstable_retries(
            session=MagicMock(),
            flagged=[(vuln_id, RegressionOutcome.UNSTABLE)],
            request_id="req-4",
        )

    enqueue_mock.assert_not_awaited()
