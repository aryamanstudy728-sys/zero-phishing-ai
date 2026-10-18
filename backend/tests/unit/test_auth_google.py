"""
Unit tests for the Google authentication service.
Tests the REAL verify_google_token function with mocked dependencies.
"""
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import redis.asyncio as redis
from fastapi import HTTPException, status

from app.services.auth_google import verify_google_token


@pytest.fixture(autouse=True)
def _isolate_from_real_redis(monkeypatch):
    """No test in this module may touch a real Redis. get_redis_client is
    patched to resolve to None by default, so verify_google_token skips both
    the success and failure caches. Tests that need a fake Redis override the
    same target inside their own patch(...) context."""
    monkeypatch.setattr(
        "app.services.auth_google.get_redis_client",
        AsyncMock(return_value=None),
    )


@pytest.mark.asyncio
async def test_verify_google_token_non_200_response():
    """Test that non-200 response from Google returns 401."""
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        mock_get_redis.return_value = None  # No Redis: no failure cache
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = AsyncMock()
        mock_response.status_code = 400
        mock_client.get.return_value = mock_response

        with pytest.raises(HTTPException) as exc_info:
            await verify_google_token("invalid-token")
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Invalid authentication token"


@pytest.mark.asyncio
async def test_verify_google_token_wrong_audience():
    """Test that wrong audience returns 401."""
    token_info = {
        "aud": "wrong-client-id",
        "azp": "wrong-client-id",
        "exp": "1792026442",
        "expires_in": "3452",
        "sub": "100000000000000000001",
        "email": "user@example.com",
        "email_verified": "true",
    }
    
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.config.get_settings") as mock_get_settings, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        
        mock_get_redis.return_value = None  # No Redis: no failure cache
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = token_info
        mock_client.get.return_value = mock_response
        
        mock_settings = MagicMock()
        mock_settings.google_client_id = "correct-client-id"
        mock_settings.user_hash_secret = "test-secret"
        mock_settings.is_production = False
        mock_get_settings.return_value = mock_settings
        
        with pytest.raises(HTTPException) as exc_info:
            await verify_google_token("any-token")
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Invalid authentication token audience"


@pytest.mark.asyncio
async def test_verify_google_token_same_sub_same_hash():
    """Test that two different tokens with same sub give same hash."""
    token_info = {
        "aud": "test-client-id",
        "azp": "test-client-id",
        "exp": "1792026442",
        "expires_in": "3452",
        "sub": "100000000000000000001",  # Same sub
        "email": "user@example.com",
        "email_verified": "true",
    }
    
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.config.get_settings") as mock_get_settings, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = token_info
        mock_client.get.return_value = mock_response
        
        mock_settings = MagicMock()
        mock_settings.google_client_id = "test-client-id"
        mock_settings.user_hash_secret = "test-secret"
        mock_settings.is_production = False
        mock_get_settings.return_value = mock_settings
        
        # Mock Redis to return None (no cache) so we go to Google
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        mock_redis.setex.return_value = True
        mock_get_redis.return_value = mock_redis
        
        # Call verify_google_token twice with different tokens but same sub info
        hash1 = await verify_google_token("token-1")
        hash2 = await verify_google_token("token-2")
        
        # Should be the same hash since sub is the same
        assert hash1 == hash2
        assert len(hash1) == 64


@pytest.mark.asyncio
async def test_verify_google_token_different_sub_different_hash():
    """Test that different sub gives different hash."""
    token_info_1 = {
        "aud": "test-client-id",
        "azp": "test-client-id",
        "exp": "1792026442",
        "expires_in": "3452",
        "sub": "100000000000000000001",  # First sub
        "email": "user1@example.com",
        "email_verified": "true",
    }
    
    token_info_2 = {
        "aud": "test-client-id",
        "azp": "test-client-id",
        "exp": "1792026442",
        "expires_in": "3452",
        "sub": "100000000000000000002",  # Second sub
        "email": "user2@example.com",
        "email_verified": "true",
    }
    
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.config.get_settings") as mock_get_settings, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        
        mock_settings = MagicMock()
        mock_settings.google_client_id = "test-client-id"
        mock_settings.user_hash_secret = "test-secret"
        mock_settings.is_production = False
        mock_get_settings.return_value = mock_settings
        
        # Mock Redis to return None (no cache) so we go to Google
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        mock_redis.setex.return_value = True
        mock_get_redis.return_value = mock_redis
        
        # First call
        mock_response_1 = MagicMock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = token_info_1
        mock_client.get.return_value = mock_response_1
        hash1 = await verify_google_token("token-1")
        
        # Second call
        mock_response_2 = MagicMock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = token_info_2
        mock_client.get.return_value = mock_response_2
        hash2 = await verify_google_token("token-2")
        
        # Should be different hashes since sub is different
        assert hash1 != hash2
        assert len(hash1) == 64
        assert len(hash2) == 64


@pytest.mark.asyncio
async def test_verify_google_token_redis_errors_fallback_to_google():
    """Test that Redis errors fall back to checking with Google."""
    token_info = {
        "aud": "test-client-id",
        "azp": "test-client-id",
        "exp": "1792026442",
        "expires_in": "3452",
        "sub": "100000000000000000001",
        "email": "user@example.com",
        "email_verified": "true",
    }
    
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.config.get_settings") as mock_get_settings, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = token_info
        mock_client.get.return_value = mock_response
        
        mock_settings = MagicMock()
        mock_settings.google_client_id = "test-client-id"
        mock_settings.user_hash_secret = "test-secret"
        mock_settings.is_production = False
        mock_get_settings.return_value = mock_settings
        
        # Mock Redis to raise exceptions on all calls
        mock_redis = AsyncMock()
        mock_redis.get.side_effect = Exception("Redis error")
        mock_redis.setex.side_effect = Exception("Redis error")
        mock_redis.ping.side_effect = Exception("Redis error")
        mock_get_redis.return_value = mock_redis
        
        # Should still work by falling back to Google
        result = await verify_google_token("any-token")
        
        # Should have called Google (the mock should have been called)
        assert mock_client.get.call_count >= 1
        assert result is not None
        assert len(result) == 64


@pytest.mark.asyncio
async def test_verify_google_token_failed_token_cached():
    """Test that a failed token is cached so second call doesn't contact Google."""
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.services.auth_google.settings") as mock_settings, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 401  # Non-200 response
        mock_client.get.return_value = mock_response
        
        mock_settings.google_client_id = "test-client-id"
        mock_settings.user_hash_secret = "test-secret"
        mock_settings.is_production = False
        
        # Mock Redis with a simple in-memory store
        redis_store = {}
        
        async def mock_get(key):
            return redis_store.get(key)
        
        async def mock_setex(key, ttl, value):
            redis_store[key] = value
            return True
            
        mock_redis = AsyncMock()
        mock_redis.get.side_effect = mock_get
        mock_redis.setex.side_effect = mock_setex
        mock_get_redis.return_value = mock_redis
        
        # First call - should contact Google and cache the failure
        with pytest.raises(HTTPException):
            await verify_google_token("failed-token")
        
        # Verify that we cached something in the failure cache
        token_hash = hashlib.sha256("failed-token".encode()).hexdigest()
        assert f"google_token_failure:{token_hash}" in redis_store
        
        # Second call - should get cached failure and NOT contact Google again
        with pytest.raises(HTTPException) as exc_info:
            await verify_google_token("failed-token")
        
        # Google should only have been called once
        assert mock_client.get.call_count == 1
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_verify_google_token_empty_client_id_server_error():
    """Test that empty client ID returns server error."""
    with patch("app.services.auth_google.settings") as mock_settings:
        mock_settings.google_client_id = ""  # Empty client ID
        mock_settings.user_hash_secret = "test-secret"
        mock_settings.is_production = False
        
        with pytest.raises(HTTPException) as exc_info:
            await verify_google_token("any-token")
        
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert exc_info.value.detail == "Server misconfiguration"


@pytest.mark.asyncio
async def test_verify_google_token_google_unreachable():
    """Test that when Google cannot be reached, returns 503."""
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        mock_get_redis.return_value = None  # No Redis: no failure cache
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = httpx.RequestError("Network error")
        
        with patch("app.services.auth_google.settings") as mock_settings:
            mock_settings.google_client_id = "test-client-id"
            mock_settings.user_hash_secret = "test-secret"
            mock_settings.is_production = False
            
            with pytest.raises(HTTPException) as exc_info:
                await verify_google_token("any-token")
            
            assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            assert exc_info.value.detail == "Could not verify authentication token"


@pytest.mark.asyncio
async def test_verify_google_token_invalid_expires_in():
    """Test that invalid expires_in is treated as failed token."""
    token_info = {
        "aud": "test-client-id",
        "azp": "test-client-id",
        "exp": "1792026442",
        "expires_in": "not-a-number",  # Invalid expires_in
        "sub": "100000000000000000001",
        "email": "user@example.com",
        "email_verified": "true",
    }
    
    with patch("httpx.AsyncClient") as mock_client_class, \
         patch("app.services.auth_google.settings") as mock_settings, \
         patch("app.services.auth_google.get_redis_client") as mock_get_redis:
        
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = token_info
        mock_client.get.return_value = mock_response
        
        mock_settings.google_client_id = "test-client-id"
        mock_settings.user_hash_secret = "test-secret"
        mock_settings.is_production = False
        
        # Mock Redis 
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None  # No cached failure
        mock_redis.setex.return_value = True
        mock_get_redis.return_value = mock_redis
        
        with pytest.raises(HTTPException) as exc_info:
            await verify_google_token("any-token")
        
        assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
        assert exc_info.value.detail == "Invalid authentication token"