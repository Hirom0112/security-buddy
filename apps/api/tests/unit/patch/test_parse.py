"""Patch-Agent parser tests."""

from __future__ import annotations

import pytest

from src.agents.patch.parse import (
    PatchParseError,
    parse_file_selection,
    parse_patch_draft,
)

_VALID_SELECTION = """{
    "file_paths": ["src/openemr/copilot/router.py", "src/openemr/copilot/guards.py"],
    "reasoning": "The narrative-containment filter is invoked from router.py and the boundary checks live in guards.py."
}"""

_VALID_DRAFT = """{
    "commit_message": "fix(security): contain narrative leakage for out-of-panel patients",
    "pr_title": "Containment filter for cross-patient narrative leakage",
    "pr_body": "Closes VUL-0001.\\n\\nOWASP LLM: LLM02\\nMITRE ATLAS: AML.T0048\\n\\n## Reviewer checklist\\n- [ ] Confirms regression fixture",
    "justification": "We strip any patient_id outside session_context.patient_ids before rendering.",
    "files": [
        {"path": "src/openemr/copilot/guards.py", "contents": "def contain(...): ..."}
    ]
}"""


def test_parse_selection_valid() -> None:
    sel = parse_file_selection(_VALID_SELECTION)
    assert "src/openemr/copilot/router.py" in sel.file_paths
    assert len(sel.file_paths) == 2


def test_parse_selection_fenced() -> None:
    fenced = f"```json\n{_VALID_SELECTION}\n```"
    sel = parse_file_selection(fenced)
    assert sel.file_paths[0] == "src/openemr/copilot/router.py"


def test_parse_selection_empty_raises() -> None:
    with pytest.raises(PatchParseError):
        parse_file_selection("")


def test_parse_selection_no_paths_raises() -> None:
    bad = '{"file_paths": [], "reasoning": "none"}'
    with pytest.raises(PatchParseError):
        parse_file_selection(bad)


def test_parse_draft_valid() -> None:
    draft = parse_patch_draft(_VALID_DRAFT)
    assert draft.commit_message.startswith("fix(security):")
    assert len(draft.files) == 1
    assert draft.files[0].path.endswith("guards.py")


def test_parse_draft_extra_fields_rejected() -> None:
    bad = _VALID_DRAFT.replace(
        '"justification":',
        '"unexpected": "value", "justification":',
    )
    with pytest.raises(PatchParseError):
        parse_patch_draft(bad)


def test_parse_draft_unbalanced_json() -> None:
    with pytest.raises(PatchParseError):
        parse_patch_draft('{"commit_message": "x", "files": [')
