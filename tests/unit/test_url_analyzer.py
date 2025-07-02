import pytest
from pydantic import AnyHttpUrl

from src.analysis.url_analyzer import run_analysis
from src.analysis.schema import AnalysisDetail

@pytest.mark.asyncio
async def test_run_analysis_orchestrates_checks_correctly(mocker):
    """Unit test for run_analysis
    GIVEN: Mocked check modules and scorer
    WHEN: run_analysis is executed
    THEN: Should execute run() on each check, parse results to scorer and return correctly parsed dict
    """
    test_url = AnyHttpUrl("http://example.com")

    #1. Create Mock AnalysisDetail results
    mock_1 = AnalysisDetail(check_name="check 1", is_suspicious=True, score_impact=10, details="Details 1")
    mock_2 = AnalysisDetail(check_name="check 2", is_suspicious=False, score_impact=0, details="Details 2")

    #2. Mock URL_CHECKS with mock.patch
    mock_1_check = mocker.AsyncMock()
    mock_1_check.run.return_value = mock_1
    mock_2_check = mocker.AsyncMock()
    mock_2_check.run.return_value = mock_2

    mocker.patch(
        "src.analysis.url_analyzer.URL_CHECKS",
        [mock_1_check, mock_2_check]
    )

    #3. Mock calculate_final_score from src/scoring/scorer.py
    #mock_scorer = mocker.patch("src.scoring.scorer.calculate_final_score", return_value=(10, "Low"))

    #4. WHEN
    final_result = await run_analysis(test_url)

    #5. Check if run() was executed on both mocks with correct URL
    mock_1_check.run.assert_awaited_once_with(test_url)
    mock_2_check.run.assert_awaited_once_with(test_url)

    #6. Check if scorer was executed with list of results from mocks
    # mock_scorer.assert_called_once_with([mock_1, mock_2])

    #7. Check if final result has correct structurer and data from scorer
    assert final_result["score"] == 10
    assert final_result["risk_level"] == "Low"
    assert len(final_result["details"]) == 2

    #8. Check if mock data was correctly converted to dict
    assert final_result["details"][0] == mock_1.model_dump()
    assert final_result["details"][1] == mock_2.model_dump()

