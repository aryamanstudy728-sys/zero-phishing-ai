// Integration tests for backend API

import pytest
from httpx import AsyncClient
from app.main import create_app

app = create_app()


@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


class TestAnalyzeEndpoint:
    @pytest.mark.asyncio
    async def test_analyze_requires_auth(self, client):
        response = await client.post("/api/v1/analyze", json={
            "message_id": "test-123",
            "provider": "gmail",
            "headers_raw": "From: test@example.com\nSubject: Test",
            "body_text": "Hello world",
            "body_html": "<p>Hello world</p>",
            "urls": []
        })
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_analyze_invalid_provider(self, client):
        response = await client.post("/api/v1/analyze",
            headers={"Authorization": "Bearer fake-token"},
            json={
                "message_id": "test-123",
                "provider": "invalid",
                "headers_raw": "From: test@example.com\nSubject: Test",
                "body_text": "Hello world",
                "body_html": "<p>Hello world</p>",
                "urls": []
            }
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_analyze_missing_fields(self, client):
        response = await client.post("/api/v1/analyze",
            headers={"Authorization": "Bearer fake-token"},
            json={
                "message_id": "test-123",
                "provider": "gmail"
            }
        )
        assert response.status_code == 422


class TestFeedbackEndpoint:
    @pytest.mark.asyncio
    async def test_feedback_requires_auth(self, client):
        response = await client.post("/api/v1/feedback", json={
            "email_id": "550e8400-e29b-41d4-a716-446655440000",
            "correction": "safe"
        })
        assert response.status_code == 401


class TestEngagementEndpoint:
    @pytest.mark.asyncio
    async def test_engagement_stats_requires_auth(self, client):
        response = await client.get("/api/v1/engagement/stats")
        assert response.status_code == 401