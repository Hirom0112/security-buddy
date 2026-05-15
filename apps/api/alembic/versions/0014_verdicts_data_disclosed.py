"""Add verdicts.data_actually_disclosed for the over-call gate.

Motivation:
  Reviewer audit found 22/22 attacks in a sample labelled "exploit" by the
  Judge, of which 7 were target-executed-OOP-query but RESPONSE-CARRIED-NO-
  DATA (empty list / 403 envelope / no clinical content). The Judge correctly
  noted the auth bypass but called them "exploit" alongside attacks that
  leaked full medication lists. Operator could not trust the queue.

  We add a second-axis signal on the verdict so consumers (Documentation
  Agent severity classifier, regression sweep aggregator, operator UI) can
  distinguish "the system did the wrong thing AND the wrong data left the
  system" from "the system did the wrong thing but the response was empty".

Schema change:
  ALTER TABLE verdicts ADD COLUMN data_actually_disclosed BOOLEAN NULL.
  Nullable on purpose — legacy verdict rows pre-dating this field have no
  value, and the Documentation Agent treats NULL as "unknown, keep the
  legacy severity behavior" for backwards compatibility.

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-15
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "verdicts",
        sa.Column(
            "data_actually_disclosed",
            sa.Boolean(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("verdicts", "data_actually_disclosed")
