
from fastapi import status

from src.analysis.schema import AnalysisDetail


def test_analyze_url_happy_path(client, mocker):
    """Integration happy path test fro URL analyzer
    GIVEN: Working app with dependencies or partially mocked dependencies
    WHEN: POST request sent to /api/v1/analysis/url
    THEN: App response should be 200 with correctly formated json
    """
    #1. Mock example functionality
    mock_redirect_result = AnalysisDetail(
        check_name="Redirect Check",
        is_suspicious=False,
        score_impact=0,
        details={"hops": 0}
    )
    mock_ssl_result = AnalysisDetail(
        check_name="SSL/TLS Certificate Check",
        is_suspicious=False,
        score_impact=0,
        details="Certificate appears valid."
    )
    #1.1 Mock URL_CHECKS
    mock_redirect_check = mocker.Mock(run=mocker.AsyncMock(return_value=mock_redirect_result))
    mock_ssl_check = mocker.Mock(run=mocker.AsyncMock(return_value=mock_ssl_result))
    mocker.patch("src.analysis.url_analyzer.URL_CHECKS", [mock_redirect_check, mock_ssl_check])
    #2. Status should be 200
    request_data = {"url":"https://no-redirect.com"}
    response = client.post("/api/v1/analysis/url", data=request_data)
    assert response.status_code == status.HTTP_200_OK
    #3. Check if json structure matches AnalysisResponse
    response_data = response.json()
    assert "score" in response_data
    assert "risk_level" in response_data
    assert "details" in response_data
    #4. Check if response values matches mocked values
    assert len(response_data["details"]) >= 1
    assert response_data["details"][0]["check_name"] == "Redirect Check"
