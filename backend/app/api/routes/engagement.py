# Engagement stats endpoint

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.database import get_db_session
from app.schemas import EngagementStatsResponse
from app.models import EngagementEvent
from app.api.deps import get_current_user_hash

router = APIRouter(prefix="/engagement", tags=["engagement"])


@router.get(
    "/stats",
    response_model=EngagementStatsResponse,
)
async def engagement_stats_endpoint(
    user_hash: str = Depends(get_current_user_hash),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Get engagement-based sender tags for the current user.
    """
    # Get sender engagement stats
    stmt = select(
        EngagementEvent.sender_email,
        func.count(EngagementEvent.id).label("open_count"),
        func.sum(
            func.case((EngagementEvent.event_type == "reply", 1), else_=0)
        ).label("reply_count"),
        func.avg(EngagementEvent.duration_ms).label("avg_dwell"),
    ).where(
        EngagementEvent.user_id == user_hash
    ).group_by(EngagementEvent.sender_email)

    result = await db.execute(stmt)
    rows = result.all()

    stats = {}
    for row in rows:
        sender = row.sender_email
        opens = row.open_count or 0
        replies = row.reply_count or 0
        avg_dwell = row.avg_dwell or 0

        # Simple tagging logic
        if replies > 0 and opens > 2:
            tag = "priority"
        elif opens > 10 and replies == 0:
            tag = "newsletter"
        elif opens == 0:
            tag = "low-engagement"
        else:
            tag = "normal"

        stats[sender] = tag

    return EngagementStatsResponse(stats=stats)