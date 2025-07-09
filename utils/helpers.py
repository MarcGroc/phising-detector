import httpx
from tenacity import AsyncRetrying, stop_after_attempt, wait_fixed, retry_if_exception_type

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
