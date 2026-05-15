"""Extend vulnerabilities.rubric_snapshot with a `full` sub-key.

CLAUDE.md §6a + Slice 6 §1 / TODO.md "Watch items: Slice 6 frozen rubric":
the documentation agent must freeze the FULL rubric at vulnerability write
time so the regression harness re-grades old findings against the rubric
that was in force at confirmation — not against a manifest that may have
drifted mid-incident.

Shape (additive, backwards-compatible):

    rubric_snapshot = {
      "rubric_version":         "...",     # existing
      "model_version":          "...",     # existing
      "violated_boundary_ids":  [...],     # existing
      "full": {                            # NEW (this migration)
        "success_criteria":         [...],
        "trust_boundaries":         [...],
        "expected_safe_behaviors":  [...],
        "manifest_id":              "...",
        "manifest_revision":        "...",
        "captured_at":              "iso8601"
      }
    }

Column type: `rubric_snapshot` is already JSONB (see migration 0002). No DDL
change to the column is required — this migration is a no-op at the schema
level. It exists so:
  1. The change has a numbered, reviewable migration entry per CLAUDE.md §6a
     ("Updating a mapping is a code commit. Not a config change.").
  2. Future readers can grep alembic/versions/ for "rubric_snapshot" and
     find the contract update.

Backfill: NOT performed. Old rows keep their two-field shape and the harness
replay path falls back to live manifest resolution when `full` is absent.
This is the documented backward-compat path in src/harness/replay.py
(_rubric_from_snapshot returns None → resolve_rubric on live manifest).

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-15
"""

from collections.abc import Sequence

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # No DDL: rubric_snapshot is already JSONB. The new `full` sub-key is an
    # application-level contract enforced by the documentation agent
    # (src/agents/documentation/rubric_snapshot.py::build_full_rubric_snapshot).
    pass


def downgrade() -> None:
    # No-op: there is nothing schema-level to revert.
    pass
