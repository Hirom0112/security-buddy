"""baseline

Revision ID: 0001
Revises:
Create Date: 2026-05-11 00:00:00.000000

Empty baseline migration — establishes the Alembic revision chain.
All real schema is in 0002_core_schema.py.
"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """No-op: this migration exists only to anchor the revision chain."""
    pass


def downgrade() -> None:
    """No-op: nothing to undo."""
    pass
