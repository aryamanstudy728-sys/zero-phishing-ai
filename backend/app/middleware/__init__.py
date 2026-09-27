# Middleware for logging, rate limiting, etc.

import time
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.config import get_settings

settings = get_settings()
logger = structlog.get_logger()


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time

        logger.info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=int(duration * 1000),
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests: int = 100, window_seconds: int = 3600):
        super().__init__(app)
        self.requests = requests
        self.window_seconds = window_seconds
        self.cache = {}  # In production, use Redis

    async def dispatch(self, request: Request, call_next):
        # Get client identifier (IP or user hash)
        client_id = request.client.host if request.client else "unknown"
        if hasattr(request.state, "user_hash"):
            client_id = request.state.user_hash

        # Simple in-memory rate limiting
        now = time.time()
        if client_id in self.cache:
            timestamps = [t for t in self.cache[client_id] if now - t < self.window_seconds]
            if len(timestamps) >= self.requests:
                return Response(
                    content='{"error": "Rate limit exceeded"}',
                    status_code=429,
                    media_type="application/json"
                )
            timestamps.append(now)
            self.cache[client_id] = timestamps
        else:
            self.cache[client_id] = [now]

        # Clean old entries periodically
        if len(self.cache) > 10000:
            cutoff = now - self.window_seconds
            self.cache = {k: [t for t in v if t > cutoff] for k, v in self.cache.items()}

        return await call_next(request)