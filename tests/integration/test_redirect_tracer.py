from fastapi import status

API_PATH = "/api/v1/analysis/url"
URL = "https://example.com"


def test_no_redirects_happy_path(client, mock_trace_redirects):
    """Test happy path when no redirects"""
    request_data = {"url": URL}
    response = client.post(API_PATH, data=request_data)

    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()
    assert response_data["score"] >= 0
    assert response_data["details"][0]["is_suspicious"] is False


def test_redirect_when_redirects(client, mock_trace_redirects, mocker):
    mock_trace_redirects.return_value = mocker.Mock(
        was_redirected=True,
        chain_completed=True,
        final_url=URL,
        redirect_chain=[mocker.Mock()]
    )
    request_data = {"url": str(URL)}

    response = client.post(API_PATH, data=request_data)
    assert response.status_code == status.HTTP_200_OK
    response_data = response.json()
    assert response_data["score"] > 1
    assert response_data["details"][0]["is_suspicious"] is True
