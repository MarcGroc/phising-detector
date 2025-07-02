import httpx
from pydantic import AnyHttpUrl
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

from analysis.schema import AnalysisDetail
from src.analysis.redirect_tracer.schema import RedirectHop, RedirectTraceResult
from src.analysis.schema import AbstractCheck

from typing import Optional, Generic, TypeVar

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
@retry(stop=stop_after_attempt(3),
       wait=wait_fixed(1),
       retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
       )
async def _perform_trace_redirects(url: AnyHttpUrl) -> RedirectTraceResult:
    """Trace redirects chain and return result in json"""

    async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
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


async def get_redirect_trace(url: AnyHttpUrl) -> RedirectTraceResult:
    """Throw exception if @retry _perform_trace_redirects fails"""
    try:
        result = await _perform_trace_redirects(url)
        return result
    except httpx.RequestError as e:
        logger.warning(f"Redirects check  for {url} failed with error: {e}")
        return RedirectTraceResult(was_redirected=False, final_url=url, redirect_chain=[], chain_completed=False)


class RedirectCheck(AbstractCheck):
    """Check if URL is redirected"""

    @property
    def name(self) -> str:
        return "Redirect Check"

    async def run(self, url: AnyHttpUrl) -> AnalysisDetail:
        trace_result = await _perform_trace_redirects(url)
        is_suspicious = trace_result.was_redirected
        score_impact = 10 if is_suspicious else 0

        details = {"chain_completed": trace_result.chain_completed,
                   "final_url": trace_result.final_url,
                   "hops": len(trace_result.redirect_chain)}
        return AnalysisDetail(check_name=self.name,
                              is_suspicious=is_suspicious,
                              score_impact=score_impact,
                              details=details)
