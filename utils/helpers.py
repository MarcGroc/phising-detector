import json
from pathlib import Path

import httpx
from loguru import logger
from tenacity import AsyncRetrying, stop_after_attempt, wait_fixed, retry_if_exception_type

__all__= ["create_http_retryer", "load_brands_list"]
# Basic constants for AsyncRetrying
ATTEMPTS: int = 3
WAIT_SECONDS: int = 2

# Exception constants for AsyncRetrying
DEFAULT_RETRY_EXCEPTIONS = (httpx.TimeoutException, httpx.ConnectError)


def create_http_retryer(attempts: int = ATTEMPTS, wait_seconds: int = WAIT_SECONDS,
                        retry_on: tuple = DEFAULT_RETRY_EXCEPTIONS) -> AsyncRetrying:
    """Factory for AsyncRetrying"""
    return AsyncRetrying(stop=stop_after_attempt(attempts), wait=wait_fixed(wait_seconds),
                         retry=retry_if_exception_type(retry_on))

def load_brands_list(file:str) -> list:
    """Read json file and return list"""
    data = Path(__file__).parent / file
    try:
        with open(data, "r", encoding="utf-8") as json_file:
            return json.load(json_file)["top_100_pl"]
    except FileNotFoundError:
        logger.error(f"File with trusted names not found at; {data}")
        return []