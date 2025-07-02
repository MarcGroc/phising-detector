import asyncio
from loguru import logger
from pydantic import AnyHttpUrl
from src.analysis.redirect_tracer.controller import RedirectCheck
from src.scoring.scorer import calculate_final_score
#-------STRATEGY PATTERN----------

# Insert all checks in URL_CHECKS!
#-------------SEPARATION OF CONCERNS-------
URL_CHECKS = [
    RedirectCheck()
]

#---------OPEN/CLOSE PRINCIPLE---------------
async def run_analysis(url: AnyHttpUrl) -> dict:
    """Orchestration of entire URL analysis, runs all checks at the same time"""
    logger.info(f"Analyzing {url}")
    #1 prepare list of task to run
    tasks = [check.run(url) for check in URL_CHECKS] # -----OOP POLYMORPHISM------
    #2 run all tasks concurrently
    check_results = await asyncio.gather(*tasks)#------PERFORMANCE---------
    logger.info(f"Received {len(check_results)} analysis results")
    #3 Parse results to scorer
    final_score, risk_level = calculate_final_score(check_results)
    logger.success(f"Final score: {final_score}, Risk level: {risk_level}")
    #4 Return aggregated results
    return {"score": final_score, "risk_level": risk_level, "details": [result.model_dump() for result in check_results]}
