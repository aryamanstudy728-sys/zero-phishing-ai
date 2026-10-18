# API dependencies

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import get_settings
from app.services.auth_google import verify_google_token

settings = get_settings()
security = HTTPBearer(auto_error=False)


async def get_current_user_hash(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """
    Extract and verify user identity from OAuth token.
    Verifies the token with Google and returns a stable user hash.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # TODO: Support Microsoft/Outlook tokens. For now, only Google tokens are supported.
    # Non-Google tokens will fail verification with Google and return 401.
    return await verify_google_token(credentials.credentials)


async def get_optional_user_hash(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str | None:
    """Optional auth for endpoints that can work anonymously."""
    if not credentials:
        return None

    try:
        return await verify_google_token(credentials.credentials)
    except HTTPException:
        return None