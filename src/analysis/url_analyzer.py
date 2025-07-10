import asyncio
from loguru import logger
from pydantic import AnyHttpUrl

from analysis.schema import AnalysisDetail
from src.scoring.scorer import calculate_final_score
from src.analysis.redirect_tracer.controller import RedirectCheck
from src.analysis.ssl_tls_check.controller import SSLCheck
from src.analysis.fuzz_check.controller import FuzzDomainCheck
#-------STRATEGY PATTERN----------

#-------SEPARATION OF CONCERNS-------
# RedirectCheck() Must be done first and return final_url
REDIRECT_CHECK = RedirectCheck()
# Insert all checks in URL_CHECKS!
# All other checks runs on final_url
URL_CHECKS = [
    SSLCheck(),
    FuzzDomainCheck()
]

#---------OPEN/CLOSE PRINCIPLE---------------
async def run_analysis(url: AnyHttpUrl) -> dict:
    """Orchestration of entire URL analysis, runs all checks at the same time"""
    logger.info(f"Analyzing {url}")
    all_results: list[AnalysisDetail] = []
    #1 Redirect checks must be done first
    redirect_result = await REDIRECT_CHECK.run(url)
    all_results.append(redirect_result)
    if not redirect_result.details.get("chain_completed"):
        logger.warning("Redirect trace failed, no reliable final_url available")
        final_score, risk_level = calculate_final_score(all_results)
        return {
            "score": final_score,
            "risk_level": risk_level,
            "details": [res.model_dump() for res in all_results]
        }
    final_url = AnyHttpUrl(redirect_result.details["final_url"])
    logger.info(f"Final URL: {final_url}")
    #2 Run all tasks concurrently with final_url
    tasks = [check.run(final_url) for check in URL_CHECKS] # -----OOP POLYMORPHISM------
    check_results = await asyncio.gather(*tasks)#------PERFORMANCE---------
    all_results.extend(check_results)
    logger.info(f"Received {len(check_results)} analysis results")
    #3 Parse results to scorer
    final_score, risk_level = calculate_final_score(all_results)
    logger.success(f"Final score: {final_score}, Risk level: {risk_level}")
    #4 Return aggregated results
    return {"score": final_score, "risk_level": risk_level, "details": [result.model_dump() for result in all_results]}
