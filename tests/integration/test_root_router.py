from fastapi import status
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

from src.core.config import settings

def test_health_check(client: TestClient):
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()
    assert response_data["status"] == "all good"

def test_docs_redirect_if_debug(client: TestClient):
    response =client.get("/")
    assert response.status_code == status.HTTP_200_OK
    if settings.DEBUG:
        assert RedirectResponse(url='/docs').status_code == status.HTTP_307_TEMPORARY_REDIRECT
