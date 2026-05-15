"""Add notes JSONB column to vulnerabilities.

The notes column captures an append-only audit trail of operator actions
against a finding — most importantly, the *reason* an operator dismisses
a critical-severity draft. Prior to this migration, dismiss was a pure
log+no-op with no durable record; the trail is now stored on the row so
the UI and downstream audits can show who/why/when.

Schema:
    notes JSONB NOT NULL DEFAULT '[]'::jsonb

Each entry is a JSON object: {"at": ISO8601, "actor": "operator",
"action": "dismiss"|..., "reason": "..."}.

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "notes",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("vulnerabilities", "notes")
