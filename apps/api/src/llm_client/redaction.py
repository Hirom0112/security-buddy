"""Secret redaction utilities.

redact(value) recursively scrubs sensitive values from any Python object
before it is logged or serialized. Used by:
  - log_event() to filter **fields before emission
  - LLMClient before constructing log payloads

Patterns scrubbed from string values:
  - sk-...       (OpenAI-style keys, also used by some OpenRouter keys)
  - gho_...      (GitHub OAuth tokens)
  - glpat-...    (GitLab PATs)
  - JWT-like strings (three base64url segments separated by dots)
  - Bearer <token> authorization headers

Dict keys matching the regex (case-insensitive):
  password | secret | token | api[_-]?key | authorization
are replaced wholesale with the string "<redacted>".
"""

import re
from typing import Any

# --- Regex patterns for sensitive string content ---
_PATTERN_SK = re.compile(r"sk-[A-Za-z0-9_-]{20,}")
_PATTERN_GHO = re.compile(r"gho_[A-Za-z0-9]{36,}")
_PATTERN_GLPAT = re.compile(r"glpat-[A-Za-z0-9._-]{20,}")
_PATTERN_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_PATTERN_BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._\-/+]{10,}", re.IGNORECASE)

_ALL_VALUE_PATTERNS = (
    _PATTERN_SK,
    _PATTERN_GHO,
    _PATTERN_GLPAT,
    _PATTERN_JWT,
    _PATTERN_BEARER,
)

# Keys whose values are always replaced regardless of the value's content.
_SENSITIVE_KEY = re.compile(r"(?i)(password|secret|token|api[_-]?key|authorization)")

_REDACTED = "<redacted>"


def _scrub_string(value: str) -> str:
    """Replace sensitive sub-strings within a single string."""
    for pattern in _ALL_VALUE_PATTERNS:
        value = pattern.sub(_REDACTED, value)
    return value


def redact(value: Any) -> Any:
    """Recursively scrub secrets from value.

    - str: replace pattern matches in-place.
    - dict: replace values of sensitive-named keys; recurse into others.
    - list/tuple: recurse into each element (returns a list).
    - Everything else: returned unchanged.

    The return type matches the structure of the input (dicts stay dicts,
    lists stay lists, strings stay strings).
    """
    if isinstance(value, str):
        return _scrub_string(value)

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and _SENSITIVE_KEY.search(k):
                result[k] = _REDACTED
            else:
                result[k] = redact(v)
        return result

    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]

    return value
