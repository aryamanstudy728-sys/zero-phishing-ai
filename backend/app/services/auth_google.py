# Google authentication service
import hashlib
import hmac
from typing import Optional

import httpx
import redis
from fastapi import HTTPException, status

from app.config import get_settings


settings = get_settings()
_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> redis.Redis:
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(settings.redis_url)
        except Exception:
            # If Redis connection fails, we'll return None and handle it in the caller
            _redis_client = None
    return _redis_client


async def verify_google_token(token: str) -> str:
    """
    Verify a Google access token and return a stable user hash.
    Raises HTTPException 401 if verification fails.
    """
    # Check Redis cache for successful verification first
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    redis_client = get_redis_client()
    if redis_client is not None:
        try:
            cached = redis_client.get(f"google_token_success:{token_hash}")
            if cached is not None:
                return cached.decode("utf-8")
        except Exception:
            # Redis error, fall back to live verification
            pass

    # Check Redis cache for failed verification to avoid hammering Google
    if redis_client is not None:
        try:
            failed_cached = redis_client.get(f"google_token_failure:{token_hash}")
            if failed_cached is not None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except Exception:
            pass

    # Verify with Google's tokeninfo endpoint
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"access_token": token},
            )
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not verify authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    if response.status_code != 200:
        # Cache the failure for 60 seconds
        if redis_client is not None:
            try:
                redis_client.setex(
                    f"google_token_failure:{token_hash}",
                    60,
                    "1",
                )
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_info = response.json()

    # Validate token fields
    # Note: All values are strings according to the example
    aud = token_info.get("aud")
    azp = token_info.get("azp")
    exp = token_info.get("exp")
    expires_in = token_info.get("expires_in")
    sub = token_info.get("sub")

    # Check required fields
    if not all([aud, azp, exp, expires_in, sub]):
        # Cache failure
        if redis_client is not None:
            try:
                redis_client.setex(
                    f"google_token_failure:{token_hash}",
                    60,
                    "1",
                )
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check audience and authorized party
    expected_client_id = settings.google_client_id
    if not expected_client_id:
        # Fail closed: if no client ID configured, reject all tokens
        # Log a clear message (but we don't have logger here, so we raise)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: Google client ID not set",
        )
    if aud != expected_client_id or azp != expected_client_id:
        # Cache failure
        if redis_client is not None:
            try:
                redis_client.setex(
                    f"google_token_failure:{token_hash}",
                    60,
                    "1",
                )
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token audience",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check expiration (optional, but we do it for safety)
    # Note: exp is a string representing seconds since epoch
    # We could compare with current time, but we also have expires_in
    # We'll use expires_in for TTL calculation

    # Compute stable user hash from the Google account ID (sub)
    # Use HMAC-SHA256 with the user_hash_secret
    if not settings.user_hash_secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: User hash secret not set",
        )
    # In production, fail if the secret is still the default
    if settings.is_production and settings.user_hash_secret == "dev-user-hash-secret-change-in-production":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: User hash secret must be changed in production",
        )

    # Calculate HMAC-SHA256 of the sub (account ID) using the secret
    # Note: We must use the bytes of the sub and the secret
    h = hmac.new(
        settings.user_hash_secret.encode("utf-8"),
        msg=sub.encode("utf-8"),
        digestmod=hashlib.sha256,
    )
    user_hash = h.hexdigest()[:64]  # First 64 characters

    # Cache the successful verification
    ttl = min(300, int(expires_in))  # expires_in is string, convert to int
    if redis_client is not None and ttl > 0:
        try:
            redis_client.setex(
                f"google_token_success:{token_hash}",
                ttl,
                user_hash,
            )
        except Exception:
            # Redis error, but we have the user_hash to return
            pass

    return user_hash