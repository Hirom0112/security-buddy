"""Structured JSON event emission.

Every call to log_event() emits exactly one JSON line to stdout via the
standard library logging module configured with a JSON formatter.

The payload always includes:
  - event: the event name
  - request_id: from the ambient ContextVar (may be None for background workers)
  - ts: ISO 8601 UTC timestamp

All additional **fields are passed through redact() before emission so that
secrets never appear in logs (CLAUDE.md §2, §"Observability").

NEVER log raw attack payloads, LLM completion text, or any field that might
contain leaked PHI. Log lengths, hashes, trace IDs, and structured outcomes only.
"""

import logging
import logging.config
from datetime import UTC, datetime
from typing import Any

from src.llm_client.redaction import redact
from src.observability.context import get_request_id

_LOG_CONFIGURED = False
_logger = logging.getLogger("security_buddy")


class _JsonFormatterShim(logging.Formatter):
    """Thin shim that emits JSON via python-json-logger when available.

    Importing the untyped third-party library is isolated here so that mypy
    --strict sees only this typed class at every call site.
    """

    def __init__(self, fmt: str, datefmt: str) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._delegate: logging.Formatter | None = None
        try:
            # pythonjsonlogger does not export __all__ so mypy raises attr-defined;
            # the import succeeds at runtime (verified). The ignore covers both codes.
            from pythonjsonlogger.jsonlogger import (  # type: ignore[attr-defined]
                JsonFormatter,
            )

            self._delegate = JsonFormatter(fmt=fmt, datefmt=datefmt)
        except Exception as exc:
            # python-json-logger unavailable or misconfigured — fall back to plain text.
            logging.getLogger(__name__).debug("JSON logger unavailable: %s", exc)

    def format(self, record: logging.LogRecord) -> str:
        if self._delegate is not None:
            return self._delegate.format(record)
        return super().format(record)


def _configure_logging() -> None:
    """Configure the root logger with a JSON formatter (idempotent)."""
    global _LOG_CONFIGURED
    if _LOG_CONFIGURED:
        return

    handler = logging.StreamHandler()
    formatter = _JsonFormatterShim(
        fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(formatter)
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False
    _LOG_CONFIGURED = True


def log_event(name: str, **fields: Any) -> None:
    """Emit a structured JSON event to stdout.

    Args:
        name: The event name (e.g. "llm_call_started", "campaign_halted").
        **fields: Arbitrary structured fields. All values are redacted before
                  logging — never pass raw secrets, PHI, or completion text.
    """
    _configure_logging()

    redacted = redact(fields)
    payload: dict[str, Any] = {
        "event": name,
        "request_id": get_request_id(),
        "ts": datetime.now(UTC).isoformat(),
    }
    payload.update(redacted)
    _logger.info(name, extra=payload)
