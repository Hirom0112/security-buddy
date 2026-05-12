"""Domain error hierarchy.

All domain errors carry an HTTP-status hint and an RFC 7807-compatible
``detail`` so the global exception handler can render them uniformly.

The domain layer does NOT import from agents, repositories, routes, workers,
or llm_client (enforced by import-linter).
"""


class DomainError(Exception):
    """Base class for all domain-level errors.

    Attributes:
        message: Human-readable description (never returned raw to clients).
        http_status: Suggested HTTP status code for the RFC 7807 response.
    """

    http_status: int = 500

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(DomainError):
    """Raised when a requested aggregate root does not exist."""

    http_status = 404


class ConflictError(DomainError):
    """Raised on optimistic-locking version mismatch (409 Conflict)."""

    http_status = 409


class ValidationError(DomainError):
    """Raised when domain invariants are violated by input data."""

    http_status = 422


class AuthorizationError(DomainError):
    """Raised when an operation is not permitted for the calling principal."""

    http_status = 403


class BudgetExhaustedError(DomainError):
    """Raised when a campaign's cost budget has been fully consumed."""

    http_status = 402
