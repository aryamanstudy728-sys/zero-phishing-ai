# Engagement stats endpoint

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db_session
from app.schemas import EngagementStatsResponse
from app.api.deps import get_current_user_hash
from app.services.engagement import get_sender_tags

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
    tags = await get_sender_tags(db, user_hash)
    return EngagementStatsResponse(stats=tags)
