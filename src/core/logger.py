import sys

from loguru import logger

from core.config import settings


def setup_logger() -> None:
    # Remove default logger
    logger.remove()

    # Configure new handler
    if settings.DEBUG:
        logger.add(sys.stdout, level="DEBUG")
    else:
        logger.add(sys.stdout, level="INFO")


setup_logger()
# Log to files
