"""Build the full rubric snapshot stored on a vulnerability row.

CLAUDE.md §6a + Slice 6 §1: the Judge's rubric at confirmation time must be
frozen onto the vulnerability so the regression harness re-grades against the
SAME rubric used to confirm the exploit, not against a mid-incident manifest
update. Without this snapshot, a manifest change can silently flip an old
finding from 'exploit' to 'safe' the next time we replay it.

Why this lives in agents/documentation and not in agents/judge:
  - The documentation agent is the writer; it owns what goes into the row.
  - The judge agent owns *evaluation*, not persistence.
  - import-linter contract "agents-mutually-independent" forbids the doc
    agent from importing the judge agent. We resolve the rubric here using
    the same manifest fields the judge resolver reads; the shape we persist
    is a pure dict so the harness can consume it without touching judge code.

Snapshot shape (lives under vulnerabilities.rubric_snapshot.full):
  {
    "success_criteria":         [...],          # campaign brief
    "trust_boundaries":         [...],          # manifest_json.trust_boundaries
    "expected_safe_behaviors":  [...],          # manifest entry for this subcategory
    "manifest_id":              "<uuid>",
    "manifest_revision":        "<version>",
    "captured_at":              "<iso8601>"
  }

Backwards-compatibility: legacy rows have only
  {"rubric_version": ..., "violated_boundary_ids": [...]}
The harness's live-replay path falls back to live manifest resolution when
`full` is absent.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID


def build_full_rubric_snapshot(
    *,
    manifest_id: UUID,
    manifest_version: str,
    manifest_json: dict[str, Any],
    subcategory: str,
    success_criteria: list[Any] | dict[str, Any] | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compose the `full` sub-key of vulnerabilities.rubric_snapshot.

    Pure function — no I/O. Callers (the documentation agent) hydrate the
    manifest and brief beforehand and pass them in.

    Args:
        manifest_id: target_manifests.id at confirmation time.
        manifest_version: target_manifests.version at confirmation time.
        manifest_json: target_manifests.manifest_json blob.
        subcategory: attacks.subcategory.
        success_criteria: campaign_briefs.success_criteria; may be None when
            we documented before a brief was attached.
        now: injected clock for tests. Defaults to datetime.now(UTC).

    Returns:
        Dict suitable for storage under rubric_snapshot["full"].
    """
    captured_at = (now or datetime.now(UTC)).isoformat()

    raw_boundaries = manifest_json.get("trust_boundaries", [])
    trust_boundaries: list[Any] = list(raw_boundaries) if isinstance(raw_boundaries, list) else []

    behaviors = manifest_json.get("expected_safe_behaviors_by_subcategory", {})
    # We snapshot ONLY the behavior for this subcategory — the harness uses
    # the snapshot to re-grade exactly this attack, no need to ship every
    # subcategory's behavior into the row.
    expected_behaviors: list[dict[str, str]] = []
    if isinstance(behaviors, dict):
        entry = behaviors.get(subcategory)
        if isinstance(entry, str) and entry.strip():
            expected_behaviors.append({"subcategory": subcategory, "expected_safe_behavior": entry})

    if success_criteria is None:
        criteria: list[Any] = []
    elif isinstance(success_criteria, dict):
        criteria = [success_criteria]
    else:
        criteria = list(success_criteria)

    return {
        "success_criteria": criteria,
        "trust_boundaries": trust_boundaries,
        "expected_safe_behaviors": expected_behaviors,
        "manifest_id": str(manifest_id),
        "manifest_revision": manifest_version,
        "captured_at": captured_at,
    }


__all__ = ["build_full_rubric_snapshot"]
