# Integration tests for backend API

import uuid

import pytest
from httpx import AsyncClient, ASGITransport

# Use the SHARED app instance from app.main so the dependency_overrides set
# in tests/conftest.py actually apply to the test client's app.
from app.main import app

AUTH = {"Authorization": "Bearer fake-token"}


@pytest.fixture(autouse=True)
def fake_analysis_services(monkeypatch):
    """Replace the network-backed analysis helpers so HTTP tests stay offline."""
    from app.services.url_reputation import URLReputationResult
    from app.services.llm_analysis import LLMAnalysisResult

    async def fake_analyze_urls(urls, html=None):
        return [
            URLReputationResult(
                url=url,
                safe_browsing={"threats": []},
                phishtank=False,
                anchor_mismatch=False,
            )
            for url in urls
        ]

    async def fake_analyze_content(headers, body_text, body_html, urls):
        return LLMAnalysisResult(
            manipulation_score=5,
            tactics=[],
            summary="Legitimate email",
            confidence=0.9,
        )

    monkeypatch.setattr("app.services.verdict.analyze_domain", lambda domain: None)
    monkeypatch.setattr("app.services.verdict.analyze_urls", fake_analyze_urls)
    monkeypatch.setattr("app.services.verdict.analyze_content", fake_analyze_content)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
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
            headers=AUTH,
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
            headers=AUTH,
            json={
                "message_id": "test-123",
                "provider": "gmail"
            }
        )
        assert response.status_code == 422


class TestAnalyzeEndpointHTTP:
    """Full request path: auth -> db dependency -> analyze_email -> response model."""

    HEADERS_RAW = (
        "From: Example Sender <bounce@mail.example.com>\r\n"
        "Authentication-Results: mx.google.com;\r\n"
        " dkim=pass header.i=@example.com header.s=sel1;\r\n"
        " spf=pass smtp.mailfrom=bounce@mail.example.com;\r\n"
        " dmarc=pass header.from=example.com\r\n"
    )

    def _body(self, message_id):
        return {
            "message_id": message_id,
            "provider": "gmail",
            "headers_raw": self.HEADERS_RAW,
            "body_text": "Hello, please verify your account.",
            "body_html": "<p>Hello, please verify your account.</p>",
            "urls": ["https://example.com/verify"],
        }

    @pytest.mark.asyncio
    async def test_new_analysis_returns_valid_uuids(self, client):
        response = await client.post("/api/v1/analyze", headers=AUTH, json=self._body("http-msg-uuid"))
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] in ("safe", "suspicious", "dangerous")
        # Valid UUIDs: the old bug returned the string "None" for analysis_id
        assert str(uuid.UUID(data["analysis_id"])) == data["analysis_id"]
        assert str(uuid.UUID(data["email_id"])) == data["email_id"]
        assert data["analysis_id"] != data["email_id"]

        # The JSON response must pass the response model the extension reads
        from app.schemas import VerdictResponse
        VerdictResponse.model_validate(data)

    @pytest.mark.asyncio
    async def test_cached_second_call_returns_same_ids(self, client):
        first = await client.post("/api/v1/analyze", headers=AUTH, json=self._body("http-msg-cache"))
        second = await client.post("/api/v1/analyze", headers=AUTH, json=self._body("http-msg-cache"))
        assert first.status_code == 200
        assert second.status_code == 200
        assert second.json()["analysis_id"] == first.json()["analysis_id"]
        assert second.json()["email_id"] == first.json()["email_id"]


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

    @pytest.mark.asyncio
    async def test_stats_returns_only_own_senders_tags(self, client, db_session):
        from app.models import EngagementEvent

        # The auth mock maps any Bearer token to "test-user-hash"
        def add(sender, event_type, user="test-user-hash"):
            db_session.add(EngagementEvent(
                user_id=user,
                sender_email=sender,
                sender_domain=sender.split("@")[-1],
                event_type=event_type,
            ))

        for _ in range(11):
            add("news@example.com", "open")
        for _ in range(3):
            add("lead@corp.example.com", "open")
        add("lead@corp.example.com", "reply")
        # Another user's sender must not appear in this user's stats
        add("other@example.com", "open", user="someone-else-hash")
        await db_session.flush()

        response = await client.get("/api/v1/engagement/stats", headers=AUTH)
        assert response.status_code == 200
        stats = response.json()["stats"]
        assert stats["news@example.com"] == "newsletter"
        assert stats["lead@corp.example.com"] == "priority"
        assert "other@example.com" not in stats