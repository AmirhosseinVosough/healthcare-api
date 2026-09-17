"""Gives every request an id, so its audit lines can be tied together."""

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

HEADER = "X-Request-ID"


class RequestId(BaseHTTPMiddleware):
    """One id per request, echoed back in the reply.

    Taken from the incoming header when there is one, so an id set by a load
    balancer or another service survives the hop and a single user action can
    be followed across several services rather than stopping at our door.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get(HEADER) or str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[HEADER] = request_id
        return response
