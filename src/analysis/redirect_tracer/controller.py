import httpx
from typing import Optional, Generic, TypeVar
from pydantic import AnyHttpUrl
from loguru import logger
from tenacity import RetryError

from src.analysis.schema import AnalysisDetail
from src.analysis.redirect_tracer.schema import RedirectHop, RedirectTraceResult
from src.analysis.schema import AbstractCheck
from src.scoring.constants import ImpactScore
from utils.helpers import create_http_retryer
from utils.constants import HEADERS
# --------- Linked List---------------
T = TypeVar('T')  # type placeholder


class Node(Generic[T]):  # unknown type yet
    def __init__(self, value: T, next_node: Optional['Node[T]'] = None):  # forward reference, otherwise Name error
        self.value = value
        self.next = next_node


def linkedlist_to_pydantic(head: Optional[Node[RedirectHop]]) -> list[RedirectHop]:
    """Convert linked list to pydantic serializable list"""

    pydantic_list = []
    current = head
    while current:
        pydantic_list.append(current.value)
        current = current.next
    return pydantic_list


# --------------------------------------
# @retry(stop=stop_after_attempt(3),
#        wait=wait_fixed(1),
#        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
#        )
async def _perform_trace_redirects(url: AnyHttpUrl) -> RedirectTraceResult:
    """Trace redirects chain and return result in json"""
    # todo imitacja przeglądarki
    async with httpx.AsyncClient(follow_redirects=True, timeout=10, headers=HEADERS) as client:
        # Use HEAD request
        response = await client.head(str(url))
        # -------- Linked list---------------
        head: Optional[Node[RedirectHop]] = None
        current: Optional[Node[RedirectHop]] = None
        # -------- Linked list---------------

        # Loop through response history
        for redirect_hop in response.history:
            hop = RedirectHop(source_url=str(redirect_hop.url),
                              target_url=redirect_hop.headers.get('location', str(redirect_hop.url)),
                              status_code=redirect_hop.status_code)
            # -------- Linked list implementation-----------
            new_node = Node(hop)
            if head is None:
                head = new_node
                current = head
            else:
                current.next = new_node
                current = new_node
        pydantic_chain = linkedlist_to_pydantic(head)
        # -----------------------------------------------------
        final_url = AnyHttpUrl(str(response.url))

        return RedirectTraceResult(was_redirected=bool(pydantic_chain), final_url=final_url,
                                   redirect_chain=pydantic_chain,
                                   chain_completed=True)


class RedirectCheck(AbstractCheck):
    """Check if URL is redirected and return redirect details"""
    __ATTEMPTS: int = 3

    @property
    def name(self) -> str:
        return "Redirect Check"

    async def run(self, url: AnyHttpUrl) -> AnalysisDetail:
        # 1. AsyncRetrying instead of retry decorator, solves issue with @retry and httpx
        retryer = create_http_retryer()

        # 2. Try again if exception in retry_if_exception_type, then RetryError
        try:
            async for attempt in retryer:
                with attempt:
                    trace_result = await _perform_trace_redirects(url)


        except RetryError as e:
            logger.warning(
                f"Redirects check for {url} failed after {self.__ATTEMPTS} retries. Error: {e.last_attempt.attempt_number}")
            trace_result = RedirectTraceResult(
                was_redirected=False,
                final_url=url,
                redirect_chain=[],
                chain_completed=False
            )
        # 3. Return results
        is_suspicious = trace_result.was_redirected
        score_impact = ImpactScore.REDIRECTED if is_suspicious else ImpactScore.ZERO

        details = {
            "chain_completed": trace_result.chain_completed,
            "final_url": str(trace_result.final_url),
            "hops": len(trace_result.redirect_chain)
        }

        return AnalysisDetail(
            check_name=self.name,
            is_suspicious=is_suspicious,
            score_impact=score_impact,
            details=details
        )
# todo https://lnkd.in/e4H33y5g
