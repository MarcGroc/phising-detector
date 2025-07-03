import pytest
import pytest_asyncio
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

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

@pytest.fixture
def mock_trace_redirects(mocker) -> MagicMock:
    mock = mocker.patch("src.analysis.redirect_tracer.controller._perform_trace_redirects")
    # Tests can modify mocked values
    mock.return_value = mocker.Mock(
        was_redirected=False,
        chain_completed=True,
        final_url="http://default-mock-url.com",
        redirect_chain=[]
    )
    return mock