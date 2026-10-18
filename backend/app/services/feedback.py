# Feedback service

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import Email, UserFeedback, Verdict
from uuid import UUID


async def submit_feedback(
    db: AsyncSession,
    user_hash: str,
    email_id: UUID,
    correction: str,
    note: str | None
) -> None:
    """Submit user feedback on a verdict."""
    # Verify email exists and belongs to this user
    stmt = select(Email).where(Email.id == email_id, Email.user_id == user_hash)
    result = await db.execute(stmt)
    email = result.scalar_one_or_none()

    if not email:
        raise ValueError("Email not found")

    # Check if feedback already exists
    fb_stmt = select(UserFeedback).where(UserFeedback.email_id == email_id)
    fb_result = await db.execute(fb_stmt)
    existing = fb_result.scalar_one_or_none()

    if existing:
        existing.correction = correction
        existing.note = note
    else:
        feedback = UserFeedback(
            email_id=email_id,
            user_id=user_hash,
            correction=correction,
            note=note,
        )
        db.add(feedback)

    await db.commit()