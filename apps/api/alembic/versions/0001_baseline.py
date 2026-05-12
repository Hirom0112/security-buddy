"""baseline

Revision ID: 0001
Revises:
Create Date: 2026-05-11 00:00:00.000000

Empty baseline migration — establishes the Alembic revision chain.
All real schema is in 0002_core_schema.py.
"""

from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """No-op: this migration exists only to anchor the revision chain."""
    pass


def downgrade() -> None:
    """No-op: nothing to undo."""
    pass
