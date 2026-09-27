# Engagement tracking service

from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import EngagementEvent, Email
from uuid import UUID


async def record_engagement(
    db: AsyncSession,
    user_hash: str,
    sender_email: str,
    sender_domain: str,
    event_type: str,  # open, reply, dwell
    duration_ms: int | None = None,
    email_id: UUID | None = None
) -> None:
    """Record an engagement event."""
    event = EngagementEvent(
        email_id=email_id,
        user_id=user_hash,
        sender_email=sender_email.lower(),
        sender_domain=sender_domain.lower(),
        event_type=event_type,
        duration_ms=duration_ms,
    )
    db.add(event)
    await db.commit()


async def get_sender_tags(db: AsyncSession, user_hash: str) -> dict[str, str]:
    """Compute engagement tags for all senders."""
    from sqlalchemy import func, case

    stmt = select(
        EngagementEvent.sender_email,
        func.count(EngagementEvent.id).label("open_count"),
        func.sum(case((EngagementEvent.event_type == "reply", 1), else_=0)).label("reply_count"),
        func.avg(EngagementEvent.duration_ms).label("avg_dwell"),
    ).where(
        EngagementEvent.user_id == user_hash
    ).group_by(EngagementEvent.sender_email)

    result = await db.execute(stmt)
    rows = result.all()

    tags = {}
    for row in rows:
        sender = row.sender_email
        opens = row.open_count or 0
        replies = row.reply_count or 0
        avg_dwell = row.avg_dwell or 0

        # Tagging logic
        if replies > 0 and opens > 2:
            tag = "priority"
        elif opens > 10 and replies == 0:
            tag = "newsletter"
        elif opens == 0:
            tag = "low-engagement"
        else:
            tag = "normal"

        tags[sender] = tag

    return tags