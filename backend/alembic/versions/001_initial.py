"""Initial migration

Revision ID: 001
Revises: 
Create Date: 2026-09-26

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create emails table
    op.create_table(
        'emails',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('message_id', sa.String(255), nullable=False),
        sa.Column('provider', sa.String(20), nullable=False),
        sa.Column('user_id', sa.String(64), nullable=False),
        sa.Column('headers_raw', sa.Text(), nullable=False),
        sa.Column('body_text', sa.Text(), nullable=False),
        sa.Column('body_html', sa.Text(), nullable=True),
        sa.Column('urls', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_emails_user_provider_received', 'emails', ['user_id', 'provider', 'received_at'])
    op.create_index('ix_emails_message_provider', 'emails', ['message_id', 'provider'], unique=True)

    # Create verdicts table
    op.create_table(
        'verdicts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('verdict', sa.String(20), nullable=False),
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('reasons', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('authenticity', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('url_reputation', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('llm_analysis', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('analysis_duration_ms', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email_id')
    )

    # Create engagement_events table
    op.create_table(
        'engagement_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('user_id', sa.String(64), nullable=False),
        sa.Column('sender_email', sa.String(255), nullable=False),
        sa.Column('sender_domain', sa.String(255), nullable=False),
        sa.Column('event_type', sa.String(20), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_engagement_user_sender_type', 'engagement_events', ['user_id', 'sender_email', 'event_type'])
    op.create_index('ix_engagement_user_domain_created', 'engagement_events', ['user_id', 'sender_domain', 'created_at'])

    # Create user_feedback table
    op.create_table(
        'user_feedback',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', sa.String(64), nullable=False),
        sa.Column('correction', sa.String(20), nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email_id')
    )

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_hash', sa.String(64), nullable=False),
        sa.Column('google_token_encrypted', sa.Text(), nullable=True),
        sa.Column('microsoft_token_encrypted', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_hash')
    )


def downgrade() -> None:
    op.drop_table('users')
    op.drop_table('user_feedback')
    op.drop_table('engagement_events')
    op.drop_table('verdicts')
    op.drop_table('emails')