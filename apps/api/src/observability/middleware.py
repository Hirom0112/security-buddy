"""ASGI middleware that stamps every request with a unique request_id.

The middleware reads the X-Request-Id header (if present) or generates a
UUID4. It sets the ContextVar via set_request_id() and reflects the value
back in the X-Request-Id response header.
"""

import uuid
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from src.observability.context import set_request_id


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Stamp each request with a request_id, propagate via ContextVar and header."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        rid = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        set_request_id(rid)
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response
