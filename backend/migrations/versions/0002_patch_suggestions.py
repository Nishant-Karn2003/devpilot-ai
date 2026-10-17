"""Persist patch suggestions and review decisions.

Revision ID: 0002_patch_suggestions
Revises: 0001_initial
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_patch_suggestions"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_suggestions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "analysis_id",
            sa.String(length=36),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            sa.String(length=36),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("patch", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_patch_suggestions_analysis_id", "patch_suggestions", ["analysis_id"])
    op.create_index("ix_patch_suggestions_finding_id", "patch_suggestions", ["finding_id"])


def downgrade() -> None:
    op.drop_table("patch_suggestions")
