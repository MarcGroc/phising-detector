import pytest
from fastapi.testclient import TestClient
import pytest_asyncio

from src.app_factory import create_app


@pytest.fixture(scope="session")
def anyio_backend():
    """Defines 'asyncio' as backend for async test"""
    return "asyncio"


@pytest_asyncio.fixture(scope="session")
async def client() -> TestClient:
    """Creates Testclient with session scope to avoid multiple client initialization and speedup tests"""
    app = create_app()

    with TestClient(app) as test_client:
        yield test_client
