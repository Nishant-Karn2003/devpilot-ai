"""Store the per-analysis quality-gate threshold.

Revision ID: 0004_gate_threshold
Revises: 0003_dependency_scans
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_gate_threshold"
down_revision = "0003_dependency_scans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analyses",
        sa.Column("gate_threshold", sa.String(length=20), nullable=False, server_default="high"),
    )


def downgrade() -> None:
    op.drop_column("analyses", "gate_threshold")
