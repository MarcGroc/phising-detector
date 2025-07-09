from fastapi import APIRouter, status, Request
from fastapi.responses import RedirectResponse, JSONResponse

local_redirect_router = APIRouter(prefix="/local-test", tags=["local redirect test"])


# Local redirect chain for testing module
# Use name= to build url_for(), dynamic URL building
# Redirect tracer uses HEAD request, api_route needed to use GET and HEAD
@local_redirect_router.api_route("/redirect-1", methods=["GET", "HEAD"], name="redirect-1")
def redirect_one(request:Request):
    # url_for, build dynamic url
    redirect_url = request.url_for("redirect-2")
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@local_redirect_router.api_route("/redirect-2", methods=["GET", "HEAD"], name="redirect-2")
def redirect_two(request:Request):
    redirect_url = request.url_for("final-url")

    return RedirectResponse(url=redirect_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@local_redirect_router.api_route("/final-url", methods=["GET", "HEAD"], name="final-url")
def redirect_three():
    return JSONResponse(status_code=status.HTTP_200_OK, content={"msg": " final url"})
