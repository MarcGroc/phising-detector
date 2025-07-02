import pytest
import httpx
from respx import MockRouter
from pydantic import AnyHttpUrl

from src.analysis.redirect_tracer.controller import get_redirect_trace


@pytest.mark.asyncio
async def test_trace_redirects_happy_path_with_redirects(respx_mock: MockRouter):
    # 1. Test urls
    initial_url = "http://example.com/"
    redirect_url = "http://redirect.com/"
    final_url = "http://final.com/"

    # 2. Mock redirect sequence with respx
    respx_mock.head(initial_url).mock(return_value=httpx.Response(status_code=301, headers={"location": redirect_url}))
    respx_mock.head(redirect_url).mock(return_value=httpx.Response(status_code=302, headers={"location": final_url}))
    respx_mock.head(final_url).mock(return_value=httpx.Response(status_code=200))

    #3. ACT
    result = await get_redirect_trace(AnyHttpUrl(initial_url))

    #4. ASSERTS
    assert result.was_redirected is True
    assert result.chain_completed is True
    assert str(result.final_url) == final_url
    assert len(result.redirect_chain) == 2

    #5. ASSERTS for redirect chain
    assert str(result.redirect_chain[0].source_url) == initial_url
    assert str(result.redirect_chain[0].target_url) == redirect_url
    assert result.redirect_chain[0].status_code == 301

    assert str(result.redirect_chain[1].source_url) == redirect_url
    assert str(result.redirect_chain[1].target_url) == final_url
    assert result.redirect_chain[1].status_code == 302

@pytest.mark.asyncio
async def test_trace_redirects_succeeds_on_retry(respx_mock: MockRouter):
    """Test if @retry will succeed on another attempt"""

    retry_url = "http://retry.com/"

    #1. Mock rspx side effect allows to define sequence Timeout and success
    respx_mock.head(retry_url).mock(side_effect=[httpx.TimeoutException("Not responding"),
                                                 httpx.Response(status_code=200)])
    #2. ACT
    result = await get_redirect_trace(AnyHttpUrl(retry_url))

    #3. ASSERTS
    assert result.was_redirected is False
    assert result.chain_completed is True
    assert str(result.final_url) == retry_url


@pytest.mark.asyncio
async def test_trace_redirects_fails_after_all_retries(mocker):
    """ Test trace_redirects fails after all attempts"""
    dead_url = "http://dead-server.com/"

    #1. Mock side effect with Connection error
    mocker.patch("src.analysis.redirect_tracer.controller._perform_trace_redirects",
                 side_effect=httpx.ConnectError("Not responding"))

    #2. ACT
    result = await get_redirect_trace(AnyHttpUrl(dead_url))

    # ASSERT
    assert result.was_redirected is False
    assert result.chain_completed is False # Must be False
    assert str(result.final_url) == dead_url
    assert result.redirect_chain == []