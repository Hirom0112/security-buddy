"""Parse the Judge's raw completion text into a JudgmentResponse.

Models occasionally wrap JSON in markdown fences (```json ... ```) or trail a
sentence after the object even when instructed not to. We tolerate the common
shapes deterministically; anything we cannot recover raises JudgeParseError
and the caller writes verdict='unclear' with the raw text in notes.
"""

import json
import re
from typing import Final

from pydantic import ValidationError

from src.agents.judge.schema import JudgmentResponse


class JudgeParseError(ValueError):
    """Raised when the Judge's completion cannot be parsed as JudgmentResponse."""


_FENCE_RE: Final = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _strip_fences(text: str) -> str:
    """Extract the first fenced JSON block, or return text unchanged."""
    m = _FENCE_RE.search(text)
    if m:
        return m.group(1).strip()
    return text.strip()


def _extract_object(text: str) -> str:
    """Find the outermost {...} JSON object in text.

    Counts brace depth so trailing commentary after a complete object is
    discarded. Returns the substring including both braces.
    """
    start = text.find("{")
    if start == -1:
        raise JudgeParseError("No JSON object found in completion")
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
    raise JudgeParseError("Unbalanced braces in completion")


def parse_judgment(completion_text: str) -> JudgmentResponse:
    """Parse raw LLM output into a validated JudgmentResponse.

    Raises:
        JudgeParseError: if no JSON object can be recovered or it fails schema
            validation. The caller is responsible for converting this into a
            verdict='unclear' row with the raw text preserved in notes.
    """
    if not completion_text or not completion_text.strip():
        raise JudgeParseError("Empty completion")

    candidate = _strip_fences(completion_text)
    obj_str = _extract_object(candidate)

    try:
        raw = json.loads(obj_str)
    except json.JSONDecodeError as exc:
        raise JudgeParseError(f"Invalid JSON: {exc.msg}") from exc

    try:
        return JudgmentResponse.model_validate(raw)
    except ValidationError as exc:
        raise JudgeParseError(f"Schema validation failed: {exc.error_count()} error(s)") from exc
