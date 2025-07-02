from fastapi import APIRouter, Form
from pydantic import AnyHttpUrl
from analysis.schema import AnalysisResponse
from src.analysis.url_analyzer import run_analysis

collector_router = APIRouter(prefix="/analysis", tags=["Analysis"])


@collector_router.post("/url", response_model=AnalysisResponse)
async def analyze_url_endpoint(url: AnyHttpUrl = Form(title="URL to analyze")):
    """Gets URL for analysis"""
    result = await run_analysis(url)
    return result
