import pytest
import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.models.database import Base, get_db
from app.config import Settings, get_settings


# Test database URL (SQLite for testing)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_settings() -> Settings:
    """Create test settings."""
    return Settings(
        app_name="Guardrails API Test",
        debug=True,
        environment="test",
        database_url=TEST_DATABASE_URL,
        secret_key="test-secret-key",
        vercel_ai_gateway_api_key="test-api-key",
    )


@pytest.fixture
async def test_engine():
    """Create a test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session_maker = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_maker() as session:
        yield session


@pytest.fixture
def override_get_db(test_session: AsyncSession):
    """Override the get_db dependency."""
    async def _override_get_db():
        yield test_session
    return _override_get_db


@pytest.fixture
def client(override_get_db, test_settings) -> TestClient:
    """Create a test client."""
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings

    with TestClient(app) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
async def async_client(override_get_db, test_settings) -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client."""
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def mock_ai_client():
    """Create a mock AI client."""
    mock = AsyncMock()
    mock.analyze_security.return_value = {
        "violations": [],
        "tokens_used": 100,
        "model": "claude-sonnet-4-5-20250514",
    }
    mock.analyze_standards.return_value = {
        "violations": [],
        "tokens_used": 100,
        "model": "claude-sonnet-4-5-20250514",
    }
    mock.detect_copilot_code.return_value = {
        "is_ai_generated": False,
        "confidence": 0,
        "ai_code_lines": [],
        "tokens_used": 50,
        "model": "claude-sonnet-4-5-20250514",
    }
    return mock


# Sample test data
@pytest.fixture
def sample_python_code() -> str:
    return '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

API_KEY = "sk_live_abc123xyz789"
'''


@pytest.fixture
def sample_typescript_code() -> str:
    return '''
const password = "secret123";

async function fetchData() {
    try {
        const result = await api.get("/data");
    } catch (e) {
        // ignore error
    }
}

function ProcessData(data) {
    console.log("Processing:", data);
}
'''


@pytest.fixture
def sample_clean_code() -> str:
    return '''
import os

def get_user(user_id: int) -> dict:
    """Get user by ID using parameterized query."""
    api_key = os.environ.get("API_KEY")
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
'''
