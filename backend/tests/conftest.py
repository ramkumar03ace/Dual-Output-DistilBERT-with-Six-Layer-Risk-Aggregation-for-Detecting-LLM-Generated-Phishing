"""
Shared test fixtures for the phishing detection backend.

The ML model is loaded once per test session so that all 12 tests
(including classification tests) can run without skipping.
"""

import sys
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport

# Add backend directory to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import app
from services.email_classifier import classifier


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session", autouse=True)
def load_model():
    """Load the ML model once for the entire test session."""
    if not classifier.is_loaded():
        classifier.load_model()


@pytest.fixture
async def client():
    """Async HTTP client for testing FastAPI endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
