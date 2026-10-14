"""User isolation: add user_id to unique constraint on emails

Revision ID: 002
Revises: 001
Create Date: 2026-10-14

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop the old unique index on (message_id, provider)
    op.drop_index('ix_emails_message_provider', table_name='emails')
    # Create new unique index on (user_id, message_id, provider)
    op.create_index('ix_emails_user_message_provider', 'emails', ['user_id', 'message_id', 'provider'], unique=True)


def downgrade() -> None:
    # Drop the new unique index
    op.drop_index('ix_emails_user_message_provider', table_name='emails')
    # Recreate the old unique index on (message_id, provider)
    op.create_index('ix_emails_message_provider', 'emails', ['message_id', 'provider'], unique=True)