from typing import Optional

from pydantic import BaseModel, AnyHttpUrl

__all__ = ["RedirectHop", "RedirectTraceResult"]


class RedirectHop(BaseModel):
    """Represents single hop in redirect chain"""
    source_url: AnyHttpUrl
    target_url: AnyHttpUrl
    status_code: int


class RedirectTraceResult(BaseModel):
    """Result of redirect trace analysis"""
    was_redirected: bool
    chain_completed: bool
    final_url: Optional[AnyHttpUrl] = None  # None is case of exception
    redirect_chain: list[RedirectHop]
