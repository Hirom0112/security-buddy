"""Parse the Documentation Agent's LLM output into a VulnerabilityDraft.

Same tolerance pattern as agents.judge.parse — fenced JSON, trailing prose,
brace counting. Schema validation via Pydantic. Anything we can't recover
raises DocumentationParseError; the worker writes a stub draft with the
raw text preserved.
"""

import json
import re
from typing import Final

from pydantic import ValidationError

from src.agents.documentation.schema import VulnerabilityDraft


class DocumentationParseError(ValueError):
    """Raised when the LLM output cannot be parsed as VulnerabilityDraft."""


_FENCE_RE: Final = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _strip_fences(text: str) -> str:
    m = _FENCE_RE.search(text)
    return m.group(1).strip() if m else text.strip()


def _extract_object(text: str) -> str:
    start = text.find("{")
    if start == -1:
        raise DocumentationParseError("no JSON object")
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise DocumentationParseError("unbalanced braces")


def parse_draft(completion_text: str) -> VulnerabilityDraft:
    """Parse raw LLM output into a validated VulnerabilityDraft."""
    if not completion_text or not completion_text.strip():
        raise DocumentationParseError("empty completion")

    candidate = _strip_fences(completion_text)
    obj_str = _extract_object(candidate)

    try:
        raw = json.loads(obj_str)
    except json.JSONDecodeError as exc:
        raise DocumentationParseError(f"invalid JSON: {exc.msg}") from exc

    try:
        return VulnerabilityDraft.model_validate(raw)
    except ValidationError as exc:
        raise DocumentationParseError(
            f"schema validation failed: {exc.error_count()} error(s)"
        ) from exc
