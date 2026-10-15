# Google authentication service
import hashlib
import hmac
import logging
from typing import Optional

import httpx
import redis.asyncio as redis
from fastapi import HTTPException, status

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()
_redis_client: Optional[redis.Redis] = None


async def get_redis_client() -> Optional[redis.Redis]:
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(
                settings.redis_url,
                socket_connect_timeout=0.5,
                socket_timeout=0.5,
                retry_on_timeout=False,
            )
            # Test the connection
            await _redis_client.ping()
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            # If Redis connection fails, we'll return None and handle it in the caller
            _redis_client = None
    return _redis_client


async def verify_google_token(token: str) -> str:
    """
    Verify a Google access token and return a stable user hash.
    Raises HTTPException 401 if verification fails.
    """
    print("DEBUG: Entering verify_google_token function")
    # Check misconfiguration first, before any network call
    expected_client_id = settings.google_client_id
    print(f"DEBUG: expected_client_id = {expected_client_id}")
    if not expected_client_id:
        # Fail closed: if no client ID configured, reject all tokens
        logger.error("Server misconfiguration: Google client ID not set")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration",
        )
    
    if not settings.user_hash_secret:
        logger.error("Server misconfiguration: User hash secret not set")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration",
        )
    
    # In production, fail if the secret is still the default
    if settings.is_production and settings.user_hash_secret == "dev-user-hash-secret-change-in-production":
        logger.error("Server misconfiguration: User hash secret must be changed in production")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration",
        )

    # Check Redis cache for successful verification first
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    print(f"DEBUG: token_hash = {token_hash}")
    redis_client = await get_redis_client()
    print(f"DEBUG: redis_client = {redis_client}")
    if redis_client is not None:
        try:
            cached = await redis_client.get(f"google_token_success:{token_hash}")
            print(f"DEBUG: cached from success cache = {cached}")
            if cached is not None:
                return cached.decode("utf-8")
        except Exception:
            # Redis error, fall back to live verification
            pass

    # Check Redis cache for failed verification to avoid hammering God
    print(f"DEBUG: Checking Redis failure cache for token_hash: {token_hash}")
    if redis_client is not None:
        try:
            failed_cached = await redis_client.get(f"google_token_failure:{token_hash}")
            # DEBUG: Print what we got from Redis
            print(f"DEBUG: Failed token cache check: failed_cached={failed_cached}, type={type(failed_cached)}")
            if failed_cached is not None:
                print("DEBUG: Raising HTTPException for cached failed token")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except Exception as e:
            # If we can't check the cache due to Redis issues, we'll proceed with verification
            # But don't catch HTTP exceptions that we raise ourselves
            if not isinstance(e, HTTPException):
                print(f"DEBUG: Exception in Redis failure cache check: {e}")
                pass
            else:
                # Re-raise HTTP exceptions
                raise

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
                await redis_client.setex(
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
                await redis_client.setex(
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
    if aud != expected_client_id or azp != expected_client_id:
        # Cache failure
        if redis_client is not None:
            try:
                await redis_client.setex(
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

    # Check expiration - if expires_in is not a valid number, treat as failed token
    try:
        expires_in_int = int(expires_in)
        if expires_in_int <= 0:
            raise ValueError("expires_in must be positive")
    except (ValueError, TypeError):
        # Invalid expires_in, treat as failed token
        if redis_client is not None:
            try:
                await redis_client.setex(
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

    # Compute stable user hash from the Google account ID (sub)
    # Use HMAC-SHA256 with the user_hash_secret
    h = hmac.new(
        settings.user_hash_secret.encode("utf-8"),
        msg=sub.encode("utf-8"),
        digestmod=hashlib.sha256,
    )
    user_hash = h.hexdigest()[:64]  # First 64 characters

    # Cache the successful verification
    ttl = min(300, expires_in_int)  # expires_in is now validated as int
    if redis_client is not None and ttl > 0:
        try:
            await redis_client.setex(
                f"google_token_success:{token_hash}",
                ttl,
                user_hash,
            )
        except Exception:
            # Redis error, but we have the user_hash to return
            pass

    return user_hash