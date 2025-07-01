from fastapi import APIRouter
from analysis.schema import AnalysisRequest, AnalysisResponse
from src.analysis.url_analyzer import run_analysis

collector_router = APIRouter(prefix="/analysis", tags=["Analysis"])


@collector_router.post("/url", response_model=AnalysisResponse)
async def analyze_url_endpoint(request: AnalysisRequest):
    """Gets URL for analysis"""
    result = await run_analysis(request.url)
    return result
