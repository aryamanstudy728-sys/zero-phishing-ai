# Pydantic request/response schemas

from typing import Optional
from pydantic import BaseModel, Field, HttpUrl
from uuid import UUID


class AnalysisRequest(BaseModel):
    message_id: str = Field(..., min_length=1, max_length=255)
    provider: str = Field(..., pattern="^(gmail|outlook)$")
    headers_raw: str = Field(..., min_length=1)
    body_text: str = Field(..., min_length=1)
    body_html: Optional[str] = None
    urls: list[HttpUrl] = Field(default_factory=list)

    class Config:
        json_schema_extra = {
            "example": {
                "message_id": "12345",
                "provider": "gmail",
                "headers_raw": "Received: from mail.example.com...\nFrom: sender@example.com\nSubject: Test",
                "body_text": "Hello, please verify your account...",
                "body_html": "<p>Hello, please verify your account...</p>",
                "urls": ["https://example.com/verify"]
            }
        }


class FeedbackRequest(BaseModel):
    email_id: UUID
    correction: str = Field(..., pattern="^(safe|suspicious|dangerous)$")
    note: Optional[str] = Field(None, max_length=1000)


class ReasonSchema(BaseModel):
    category: str
    detail: str
    severity: str = Field(..., pattern="^(critical|high|medium|low)$")


class VerdictResponse(BaseModel):
    verdict: str = Field(..., pattern="^(safe|suspicious|dangerous)$")
    score: int = Field(..., ge=0, le=100)
    reasons: list[ReasonSchema]
    analysis_id: UUID

    class Config:
        json_schema_extra = {
            "example": {
                "verdict": "suspicious",
                "score": 65,
                "reasons": [
                    {"category": "authenticity", "detail": "SPF fail: sending IP not authorized", "severity": "high"},
                    {"category": "url_reputation", "detail": "Link to known phishing site", "severity": "critical"},
                    {"category": "content", "detail": "Urges immediate credential entry", "severity": "high"}
                ],
                "analysis_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }


class EngagementStatsResponse(BaseModel):
    stats: dict[str, str]  # sender -> tag

    class Config:
        json_schema_extra = {
            "example": {
                "stats": {
                    "sender@example.com": "priority",
                    "newsletter@company.com": "newsletter",
                    "unknown@domain.com": "low-engagement"
                }
            }
        }


class AuthStatusResponse(BaseModel):
    google: bool
    microsoft: bool


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None