"""Stop storing raw email content: nullable columns, erase stored values

Revision ID: 003
Revises: 002
Create Date: 2026-10-18

"""
from alembic import op
import sqlalchemy as sa

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The backend still reads the email content to analyze it but no longer
    # stores it, so the content columns become nullable.
    op.alter_column('emails', 'headers_raw', existing_type=sa.Text(), nullable=True)
    op.alter_column('emails', 'body_text', existing_type=sa.Text(), nullable=True)
    # Drop the '[]' server default too, so new rows store NULL rather than '[]'
    op.alter_column('emails', 'urls', existing_type=sa.JSON(), nullable=True, server_default=None)

    # Erase the content already stored by older versions
    op.execute("UPDATE emails SET headers_raw = NULL")
    op.execute("UPDATE emails SET body_text = NULL")
    op.execute("UPDATE emails SET body_html = NULL")
    op.execute("UPDATE emails SET urls = NULL")


def downgrade() -> None:
    # NOTE: the raw email content erased in upgrade() CANNOT be restored;
    # this only restores the old NOT NULL constraints using placeholder
    # values for rows that are now NULL.
    op.execute("UPDATE emails SET headers_raw = '' WHERE headers_raw IS NULL")
    op.execute("UPDATE emails SET body_text = '' WHERE body_text IS NULL")
    op.execute("UPDATE emails SET body_html = '' WHERE body_html IS NULL")
    op.execute("UPDATE emails SET urls = '[]'::json WHERE urls IS NULL")
    op.alter_column('emails', 'urls', existing_type=sa.JSON(), nullable=False, server_default='[]')
    op.alter_column('emails', 'body_text', existing_type=sa.Text(), nullable=False)
    op.alter_column('emails', 'headers_raw', existing_type=sa.Text(), nullable=False)
