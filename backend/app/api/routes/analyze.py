# Analyze endpoint

from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db_session
from app.schemas import AnalysisRequest, VerdictResponse, ErrorResponse
from app.services.verdict import analyze_email
from app.api.deps import get_current_user_hash

router = APIRouter(prefix="/analyze", tags=["analysis"])


@router.post(
    "",
    response_model=VerdictResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        429: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def analyze_endpoint(
    request: AnalysisRequest,
    user_hash: str = Depends(get_current_user_hash),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Analyze an email for phishing indicators.
    Returns a verdict with detailed reasons.
    """
    try:
        verdict = await analyze_email(
            db=db,
            user_hash=user_hash,
            message_id=request.message_id,
            provider=request.provider,
            headers_raw=request.headers_raw,
            body_text=request.body_text,
            body_html=request.body_html,
            urls=[str(url) for url in request.urls],
        )
        return verdict
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Analysis failed")