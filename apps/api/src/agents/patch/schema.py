"""Pydantic schemas for the Patch Agent's structured outputs."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FileSelection(BaseModel):
    """The Patch Agent's pick of one or more candidate file paths.

    Output of the code-search prompt — the LLM proposes likely files to
    inspect/modify given a vulnerability report. The Patch Agent does NOT
    clone the OpenEMR repo in Slice 5; the file paths are passed to the
    diff-generator LLM as hints, and the human reviewer verifies them at
    PR review time.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    file_paths: list[str] = Field(
        min_length=1,
        max_length=5,
        description="Relative paths in the OpenEMR fork most likely to need editing.",
    )
    reasoning: str = Field(
        min_length=1,
        max_length=2000,
        description="One short paragraph explaining the file selection.",
    )


class PatchFile(BaseModel):
    """One file edit in a proposed patch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=1024)
    contents: str = Field(
        description="Full new file contents. The Patch Agent rewrites whole files "
        "rather than emitting diffs, because the human reviews the PR diff in "
        "GitHub anyway and full-file rewrites are unambiguous to apply.",
    )


class PatchDraft(BaseModel):
    """Parsed Patch-Agent LLM output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    commit_message: str = Field(min_length=1, max_length=200)
    pr_title: str = Field(min_length=1, max_length=200)
    pr_body: str = Field(min_length=1, max_length=20000)
    justification: str = Field(min_length=1, max_length=4000)
    files: list[PatchFile] = Field(min_length=1, max_length=5)
