# API dependencies

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import get_settings

# NOTE: jose is available (python-jose[cryptography] in pyproject.toml) and
# should be used here when real JWT verification is added. Removed for now
# because it was imported but never called.

settings = get_settings()
security = HTTPBearer(auto_error=False)


async def get_current_user_hash(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """
    Extract and verify user identity from OAuth token.
    For MVP, we accept the OAuth access token directly and hash it for user identification.

    TODO: In production, verify the token against Google/Microsoft before hashing.
          Use jose.jwt.decode() with the provider's public keys.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    import hashlib
    return hashlib.sha256(credentials.credentials.encode()).hexdigest()[:64]


async def get_optional_user_hash(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str | None:
    """Optional auth for endpoints that can work anonymously."""
    if not credentials:
        return None

    try:
        import hashlib
        return hashlib.sha256(credentials.credentials.encode()).hexdigest()[:64]
    except Exception:
        return None