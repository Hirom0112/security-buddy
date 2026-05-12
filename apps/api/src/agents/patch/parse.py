"""Parse Patch-Agent LLM output into PatchDraft / FileSelection.

Mirrors the tolerance pattern in agents.documentation.parse — fenced JSON,
trailing prose, brace counting. Anything we can't recover raises
PatchParseError; the worker writes a fallback draft and logs the failure.
"""

from __future__ import annotations

import json
import re
from typing import Final

from pydantic import ValidationError

from src.agents.patch.schema import FileSelection, PatchDraft


class PatchParseError(ValueError):
    """Raised when an LLM output cannot be parsed into the expected schema."""


_FENCE_RE: Final = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _strip_fences(text: str) -> str:
    m = _FENCE_RE.search(text)
    return m.group(1).strip() if m else text.strip()


def _extract_object(text: str) -> str:
    start = text.find("{")
    if start == -1:
        raise PatchParseError("no JSON object")
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
    raise PatchParseError("unbalanced JSON object")


def _load(text: str) -> dict[str, object]:
    body = _extract_object(_strip_fences(text))
    try:
        loaded = json.loads(body)
    except json.JSONDecodeError as exc:
        raise PatchParseError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(loaded, dict):
        raise PatchParseError("top-level value is not an object")
    return loaded


def parse_file_selection(text: str) -> FileSelection:
    obj = _load(text)
    try:
        return FileSelection.model_validate(obj)
    except ValidationError as exc:
        raise PatchParseError(f"FileSelection schema mismatch: {exc}") from exc


def parse_patch_draft(text: str) -> PatchDraft:
    obj = _load(text)
    try:
        return PatchDraft.model_validate(obj)
    except ValidationError as exc:
        raise PatchParseError(f"PatchDraft schema mismatch: {exc}") from exc
