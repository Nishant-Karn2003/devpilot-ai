"""Persist dependency inventories and OSV results.

Revision ID: 0003_dependency_scans
Revises: 0002_patch_suggestions
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_dependency_scans"
down_revision = "0002_patch_suggestions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dependency_scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("owner_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ecosystem", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("inventory", sa.JSON(), nullable=False),
        sa.Column("vulnerabilities", sa.JSON(), nullable=False),
        sa.Column("warnings", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_dependency_scans_owner_id", "dependency_scans", ["owner_id"])
    op.create_index("ix_dependency_scans_status", "dependency_scans", ["status"])
    op.create_index("ix_dependency_scans_created_at", "dependency_scans", ["created_at"])


def downgrade() -> None:
    op.drop_table("dependency_scans")
