"""Initial schema

Revision ID: 001
Revises:
Create Date: 2024-01-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Audit logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('event_type', sa.String(50), nullable=False, index=True),
        sa.Column('org', sa.String(255), nullable=False, index=True),
        sa.Column('repo', sa.String(255), nullable=False, index=True),
        sa.Column('pr_number', sa.Integer, nullable=True),
        sa.Column('commit_sha', sa.String(40), nullable=True),
        sa.Column('author', sa.String(255), nullable=True),
        sa.Column('action_taken', sa.String(50), nullable=False),
        sa.Column('scan_id', sa.String(36), nullable=True, index=True),
        sa.Column('violations_count', sa.Integer, default=0),
        sa.Column('details', sa.JSON, nullable=True),
        sa.Column('resolution_state', sa.String(50), default='pending'),
        sa.Column('resolved_by', sa.String(255), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('extra_data', sa.JSON, nullable=True),
    )

    # Scan results table
    op.create_table(
        'scan_results',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('org', sa.String(255), nullable=False, index=True),
        sa.Column('repo', sa.String(255), nullable=False, index=True),
        sa.Column('pr_number', sa.Integer, nullable=True),
        sa.Column('commit_sha', sa.String(40), nullable=True),
        sa.Column('file_path', sa.String(1024), nullable=False),
        sa.Column('language', sa.String(50), nullable=True),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('summary', sa.JSON, nullable=False),
        sa.Column('violations', sa.JSON, nullable=False),
        sa.Column('copilot_analysis', sa.JSON, nullable=True),
        sa.Column('enforcement_action', sa.String(50), nullable=False),
        sa.Column('processing_time_ms', sa.Integer, nullable=True),
        sa.Column('ai_model_used', sa.String(100), nullable=True),
        sa.Column('ai_tokens_used', sa.Integer, nullable=True),
    )

    # Violations table
    op.create_table(
        'violations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('scan_id', sa.String(36), sa.ForeignKey('scan_results.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('rule_id', sa.String(100), nullable=False, index=True),
        sa.Column('severity', sa.String(20), nullable=False, index=True),
        sa.Column('category', sa.String(50), nullable=False, index=True),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('file_path', sa.String(1024), nullable=False),
        sa.Column('line_start', sa.Integer, nullable=True),
        sa.Column('line_end', sa.Integer, nullable=True),
        sa.Column('owasp_mapping', sa.String(100), nullable=True),
        sa.Column('cwe_id', sa.String(50), nullable=True),
        sa.Column('is_ai_generated', sa.Boolean, default=False),
        sa.Column('resolution_state', sa.String(50), default='open'),
    )

    # Rules table
    op.create_table(
        'rules',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('category', sa.String(50), nullable=False, index=True),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('enabled', sa.Boolean, default=True),
        sa.Column('rule_type', sa.String(50), nullable=False),
        sa.Column('languages', sa.JSON, nullable=True),
        sa.Column('pattern', sa.Text, nullable=True),
        sa.Column('ai_prompt', sa.Text, nullable=True),
        sa.Column('owasp_mapping', sa.String(100), nullable=True),
        sa.Column('cwe_id', sa.String(50), nullable=True),
        sa.Column('fix_suggestion', sa.Text, nullable=True),
        sa.Column('references', sa.JSON, nullable=True),
        sa.Column('org', sa.String(255), nullable=True, index=True),
        sa.Column('repo', sa.String(255), nullable=True, index=True),
        sa.Column('rule_pack', sa.String(100), nullable=True, index=True),
    )

    # Configurations table
    op.create_table(
        'configurations',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('org', sa.String(255), nullable=False, index=True),
        sa.Column('repo', sa.String(255), nullable=True, index=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('enforcement_mode', sa.String(50), default='warning'),
        sa.Column('enabled_rule_packs', sa.JSON, nullable=True),
        sa.Column('custom_rules', sa.JSON, nullable=True),
        sa.Column('allowed_licenses', sa.JSON, nullable=True),
        sa.Column('blocked_licenses', sa.JSON, nullable=True),
        sa.Column('naming_conventions', sa.JSON, nullable=True),
        sa.Column('logging_requirements', sa.JSON, nullable=True),
        sa.Column('error_handling_patterns', sa.JSON, nullable=True),
        sa.Column('security_config', sa.JSON, nullable=True),
        sa.Column('copilot_config', sa.JSON, nullable=True),
        sa.Column('include_patterns', sa.JSON, nullable=True),
        sa.Column('exclude_patterns', sa.JSON, nullable=True),
        sa.Column('override_allowed', sa.Boolean, default=True),
        sa.Column('override_approvers', sa.JSON, nullable=True),
        sa.Column('extra_data', sa.JSON, nullable=True),
    )

    # Create unique constraint for org/repo config
    op.create_index(
        'ix_configurations_org_repo_unique',
        'configurations',
        ['org', 'repo'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index('ix_configurations_org_repo_unique', table_name='configurations')
    op.drop_table('configurations')
    op.drop_table('rules')
    op.drop_table('violations')
    op.drop_table('scan_results')
    op.drop_table('audit_logs')
