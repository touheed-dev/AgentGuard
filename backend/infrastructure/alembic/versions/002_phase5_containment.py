"""Create Phase 5 tables for approvals, incidents, and honey assets.

Revision ID: 002_phase5_containment
Revises: 001_phase2_persistence
"""
from alembic import op
import sqlalchemy as sa


revision = "002_phase5_containment"
down_revision = "001_phase2_persistence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approvals",
        sa.Column("approval_id", sa.String(128), primary_key=True),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fields_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(128), primary_key=True),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("task_id", sa.String(128), nullable=False),
        sa.Column("trace_id", sa.String(128), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("details_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("dedup_key", sa.String(255), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "honey_assets",
        sa.Column("asset_id", sa.String(128), primary_key=True),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("marker", sa.String(255), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("honey_assets")
    op.drop_table("incidents")
    op.drop_table("approvals")
