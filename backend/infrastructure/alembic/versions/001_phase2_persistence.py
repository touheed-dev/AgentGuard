"""Create Phase 2 persistence and audit foundation.

Revision ID: 001_phase2_persistence
Revises:
"""
from alembic import op
import sqlalchemy as sa


revision = "001_phase2_persistence"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("agents", sa.Column("agent_id", sa.String(128), primary_key=True), sa.Column("name", sa.String(255), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("security_state", sa.String(32), nullable=False), sa.Column("capability_version", sa.String(128), nullable=False), sa.Column("task_id", sa.String(128), nullable=False), sa.Column("security_epoch", sa.Integer, nullable=False, server_default="0"), sa.Column("scopes_json", sa.Text, nullable=False, server_default="[]"), sa.Column("allowed_tools_json", sa.Text, nullable=False, server_default="[]"), sa.Column("forbidden_tools_json", sa.Text, nullable=False, server_default="[]"))
    op.create_table("tools", sa.Column("tool_name", sa.String(128), primary_key=True), sa.Column("version", sa.String(64), nullable=False), sa.Column("description", sa.Text, nullable=False), sa.Column("input_schema_json", sa.Text, nullable=False), sa.Column("required_capability", sa.String(128), nullable=False), sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()))
    op.create_table("tasks", sa.Column("task_id", sa.String(128), primary_key=True), sa.Column("label", sa.String(255), nullable=False), sa.Column("status", sa.String(32), nullable=False, server_default="active"))
    op.create_table("executions", sa.Column("execution_id", sa.String(128), primary_key=True), sa.Column("idempotency_key", sa.String(255), nullable=False), sa.Column("request_id", sa.String(128), nullable=False), sa.Column("agent_id", sa.String(128), nullable=False), sa.Column("task_id", sa.String(128), nullable=False), sa.Column("tool_name", sa.String(128), nullable=False), sa.Column("trace_id", sa.String(128), nullable=False), sa.Column("lifecycle_state", sa.String(32), nullable=False), sa.Column("decision", sa.String(32), nullable=False), sa.Column("reason_code", sa.String(64)), sa.Column("request_fingerprint", sa.String(64), nullable=False), sa.Column("metadata_json", sa.Text, nullable=False, server_default="{}"), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.UniqueConstraint("agent_id", "task_id", "tool_name", "idempotency_key"))
    op.create_table("audit_chain_state", sa.Column("chain_id", sa.String(128), primary_key=True), sa.Column("sequence", sa.Integer, nullable=False, server_default="0"), sa.Column("current_hash", sa.String(64), nullable=False))
    op.create_table("events", sa.Column("event_id", sa.String(128), primary_key=True), sa.Column("chain_id", sa.String(128), nullable=False), sa.Column("sequence", sa.Integer, nullable=False), sa.Column("event_type", sa.String(128), nullable=False), sa.Column("event_json", sa.Text, nullable=False), sa.Column("previous_hash", sa.String(64), nullable=False), sa.Column("current_hash", sa.String(64), nullable=False), sa.Column("event_hash_algorithm", sa.String(32), nullable=False, server_default="SHA-256"), sa.Column("canonicalization", sa.String(32), nullable=False, server_default="RFC-8785"), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.UniqueConstraint("chain_id", "sequence"))
    op.create_table("outbox_events", sa.Column("outbox_id", sa.String(128), primary_key=True), sa.Column("event_type", sa.String(128), nullable=False), sa.Column("aggregate_id", sa.String(128), nullable=False), sa.Column("payload_json", sa.Text, nullable=False), sa.Column("published", sa.Boolean, nullable=False, server_default=sa.false()), sa.Column("attempts", sa.Integer, nullable=False, server_default="0"), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.Column("published_at", sa.DateTime(timezone=True)))
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END")
        op.execute("CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END")
    elif bind.dialect.name == "postgresql":
        op.execute("CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append-only'; END; $$")
        op.execute("CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON events FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation()")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update")
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_delete")
    elif bind.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_events_no_update ON events")
        op.execute("DROP FUNCTION IF EXISTS reject_audit_mutation")
    op.drop_table("outbox_events")
    op.drop_table("events")
    op.drop_table("audit_chain_state")
    op.drop_table("executions")
    op.drop_table("tasks")
    op.drop_table("tools")
    op.drop_table("agents")
