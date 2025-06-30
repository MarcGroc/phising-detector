from fastapi import APIRouter, HTTPException, status
from fastapi.responses import RedirectResponse

from src.core.config import settings
root_router = APIRouter(tags=["Root"])


@root_router.get("/", include_in_schema=False)
async def docs_redirect():
    """Endpoint that will redirect to SwagerUI in case `DEBUG`.
        Otherwise, it will raise a 404."""
    if settings.DEBUG:
        # doc_url = request.app.docs_url
        # return RedirectResponse(doc_url)
        return RedirectResponse(url='/docs')
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@root_router.get("/health", tags=["Health Check"])
def health_check():
    return {"status": "all good", "app_name": settings.PROJECT_NAME}
