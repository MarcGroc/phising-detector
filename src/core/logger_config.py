import logging
import sys

from loguru import logger


class InterceptHandler(logging.Handler):
    """Intercept loguru logs and send them to Logstash"""

    def emit(self, record) -> None:
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())

def setup_logging():
    logging.basicConfig(handlers=[InterceptHandler()], level=0)
    logger.add(sys.stdout,level="DEBUG", format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")
