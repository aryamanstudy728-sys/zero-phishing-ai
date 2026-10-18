# Pytest configuration

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.database import Base, get_db_session
from app.config import get_settings
from app.main import create_app

settings = get_settings()

# Override settings for testing - use SQLite in-memory
settings.database_url = "sqlite+aiosqlite:///:memory:"
settings.app_env = "test"
settings.debug = True


@pytest.fixture(scope="session")
def event_loop():
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def db_engine():
    engine = create_async_engine(settings.database_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine):
    async_session = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture(autouse=True)
def mock_settings(monkeypatch):
    # Override settings for testing - use SQLite in-memory
    settings.database_url = "sqlite+aiosqlite:///:memory:"
    settings.app_env = "test"
    settings.debug = True
    # Set Google client ID and user hash secret to avoid misconfiguration errors
    settings.google_client_id = "test-client-id"
    settings.user_hash_secret = "test-user-hash-secret"
    monkeypatch.setattr("app.config.get_settings", lambda: settings)


@pytest.fixture(autouse=True)
def mock_verify_google_token(monkeypatch):
    """Mock the Google token verification to return a fixed user hash."""
    async def mock_verify(token: str) -> str:
        return "test-user-hash"
    monkeypatch.setattr("app.api.deps.verify_google_token", mock_verify)


@pytest.fixture(autouse=True)
def override_get_db_dependency(db_session):
    """Override the get_db_session dependency to use the test session."""
    from app.main import app
    app.dependency_overrides[get_db_session] = lambda: db_session
    yield
    app.dependency_overrides.pop(get_db_session, None)