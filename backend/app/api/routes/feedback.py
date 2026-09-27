# Feedback endpoint

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db_session
from app.schemas import FeedbackRequest, ErrorResponse
from app.services.feedback import submit_feedback
from app.api.deps import get_current_user_hash

router = APIRouter(prefix="/feedback", tags=["feedback"])


@router.post(
    "",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
async def feedback_endpoint(
    request: FeedbackRequest,
    user_hash: str = Depends(get_current_user_hash),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Submit user feedback on a verdict (mark as incorrect).
    """
    try:
        await submit_feedback(
            db=db,
            user_hash=user_hash,
            email_id=request.email_id,
            correction=request.correction,
            note=request.note,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to submit feedback")