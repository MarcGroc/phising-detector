from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from loguru import logger
from .root_router import root_router
from src.api.api_v1.router_api_v1 import api_v1_router
from src.core.config import settings
from src.core.logger_config import setup_logging

# TODO add ensure_db_connection
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, Any]:
    setup_logging()

    logger.info(f"Initialiazing {settings.PROJECT_NAME}")
    yield
    logger.info("Shutting down...")


def create_app() -> FastAPI:
    app = FastAPI(title=settings.PROJECT_NAME, debug=settings.DEBUG, lifespan=lifespan)
    app.include_router(root_router)
    app.include_router(api_v1_router)


    return app
