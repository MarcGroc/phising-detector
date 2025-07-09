from fastapi import APIRouter
from analysis.routes import collector_router
from core.config import settings

from src.analysis.redirect_tracer.routes import local_redirect_router
api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(collector_router)
if settings.DEBUG:
    api_v1_router.include_router(local_redirect_router)