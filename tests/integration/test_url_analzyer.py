
from fastapi import status

def test_analyze_url_happy_path(client, mocker):
    """Integration happy path test fro URL analyzer
    GIVEN: Working app with dependencies or partially mocked dependencies
    WHEN: POST request sent to /api/v1/analysis/url
    THEN: App response should be 200 with correctly formated json
    """
    #1. Mock example functionality
    mocker.patch("src.analysis.redirect_tracer.controller._trace_redirects",
                 return_value=mocker.Mock(
                     was_redirected=False,
                     chain_completed=True,
                     final_url="http://no-redirect.com",
                     redirect_chain=[]
                 ))
    request_data = {"url":"http://no-redirect.com"}
    #2. Status should be 200
    response = client.post("/api/v1/analysis/url", json=request_data)
    assert response.status_code == status.HTTP_200_OK
    #3. Check if json structure matches AnalysisResponse
    response_data = response.json()
    assert "score" in response_data
    assert "risk_level" in response_data
    assert "details" in response_data
    #4. Check if response values matches mocked values
    assert response_data["score"] == 0
    assert response_data["risk_level"] == "Low"
    assert len(response_data["details"]) == 1
    assert response_data["details"][0]["check_name"] == "Redirect Check"
    assert response_data["details"][0]["is_suspicious"] is False