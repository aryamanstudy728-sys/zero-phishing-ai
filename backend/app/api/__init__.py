# Main API router

from fastapi import APIRouter
from app.api.routes import analyze, feedback, engagement

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(analyze.router)
api_router.include_router(feedback.router)
api_router.include_router(engagement.router)