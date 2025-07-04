import pytest
from pydantic import AnyHttpUrl

from src.analysis.url_analyzer import run_analysis
from src.analysis.schema import AnalysisDetail


@pytest.mark.asyncio
async def test_run_analysis_new_pipeline_happy_path(mocker):
    """
    GIVEN: A URL that will be "redirected" by a mock.
    WHEN:  run_analysis is executed.
    THEN:  It should first run RedirectCheck, get the final_url, and then
           run all other checks on that final_url.
    """
    #1.  ARRANGE
    initial_url = AnyHttpUrl("http://initial.com")
    final_url = AnyHttpUrl("http://final.com")

    # 1.1 Mock results for each check
    mock_redirect_result = AnalysisDetail(
        check_name="Redirect Check",
        is_suspicious=True,
        score_impact=10,
        details={"chain_completed": True, "final_url": str(final_url), "hops": 1}
    )
    mock_ssl_result = AnalysisDetail(
        check_name="SSL Check",
        is_suspicious=False,
        score_impact=0,
        details="Certificate OK"
    )

    # 2. Mock modules instances `url_analyzer`
    mock_redirect_check_instance = mocker.Mock(run=mocker.AsyncMock(return_value=mock_redirect_result))
    mocker.patch("src.analysis.url_analyzer.REDIRECT_CHECK", mock_redirect_check_instance)

    mock_ssl_check_instance = mocker.Mock(run=mocker.AsyncMock(return_value=mock_ssl_result))
    mocker.patch("src.analysis.url_analyzer.URL_CHECKS", [mock_ssl_check_instance])

    # 3. Mock scorer
    mock_scorer = mocker.patch("src.analysis.url_analyzer.calculate_final_score", return_value=(10, "Low"))

    # --- ACT ---
    result = await run_analysis(initial_url)

    # --- ASSERT ---
    # A. RedirectCheck executed with `initial_url`?
    mock_redirect_check_instance.run.assert_awaited_once_with(initial_url)

    # B. SSLCheck and other modules executed with `final_url`?
    mock_ssl_check_instance.run.assert_awaited_once_with(final_url)

    # C. Scorer has all_result list?
    mock_scorer.assert_called_once_with([mock_redirect_result, mock_ssl_result])

    # D. Final answer is correct
    assert result["score"] == 10
    assert result["risk_level"] == "Low"
    assert len(result["details"]) == 2
    assert result["details"][0] == mock_redirect_result.model_dump()
    assert result["details"][1] == mock_ssl_result.model_dump()


@pytest.mark.asyncio
async def test_run_analysis_stops_if_redirect_fails(mocker):
    """
    GIVEN: RedirectCheck fails to complete the redirect chain.
    WHEN:  run_analysis is executed.
    THEN:  It should NOT run any content checks and return early.
    """
    # --- ARRANGE ---
    initial_url = AnyHttpUrl("http://initial.com")

    # 1. Mock failed redirect
    mock_redirect_failure_result = AnalysisDetail(
        check_name="Redirect Check",
        is_suspicious=False,
        score_impact=0,
        details={"chain_completed": False, "final_url": str(initial_url), "hops": 0}
    )

    # 2. Mock dependencies
    mock_redirect_check_instance = mocker.Mock(run=mocker.AsyncMock(return_value=mock_redirect_failure_result))
    mocker.patch("src.analysis.url_analyzer.REDIRECT_CHECK", mock_redirect_check_instance)

    mock_content_check_instance = mocker.Mock()  # MOck for URL_CHEKS
    mocker.patch("src.analysis.url_analyzer.URL_CHECKS", [mock_content_check_instance])

    mock_scorer = mocker.patch("src.analysis.url_analyzer.calculate_final_score", return_value=(0, "None"))

    # --- ACT ---
    result = await run_analysis(initial_url)

    # --- ASSERT ---
    # A. Redirect was called?
    mock_redirect_check_instance.run.assert_awaited_once_with(initial_url)

    # B. If redirect fails other modules shouldn't be executed
    mock_content_check_instance.run.assert_not_called()

    # C. Scorer should have only one result
    mock_scorer.assert_called_once_with([mock_redirect_failure_result])

    # D. Final answer
    assert len(result["details"]) == 1
    assert result["details"][0]["check_name"] == "Redirect Check"
