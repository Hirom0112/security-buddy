"""Request-scoped context variables.

The request_id ContextVar is set by RequestIdMiddleware at the start of every
request. All code reads it via get_request_id() — never pass request_id as a
parameter through business logic (CLAUDE.md §"Observability").
"""

from contextvars import ContextVar

# Module-private ContextVar; always access via get_request_id/set_request_id.
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Return the request_id for the current async context, or None."""
    return _request_id.get()


def set_request_id(rid: str) -> None:
    """Set the request_id for the current async context."""
    _request_id.set(rid)
