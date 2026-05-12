"""Pinned model + decoding for the Patch Agent.

The Patch Agent's diffs are reviewed by a human before merge, so the model
choice is held to a softer bar than the Judge. We still hard-code the model
and temperature here so a git blame line is always available and the eval
baseline is reproducible.
"""

from typing import Final

PATCH_MODEL: Final[str] = "anthropic/claude-sonnet-4.6"
PATCH_TEMPERATURE: Final[float] = 0.0
PATCH_AGENT_TAG: Final[str] = "patch"

# Wall-clock timeout for each Patch-Agent LLM call.
PATCH_LLM_TIMEOUT_SECONDS: Final[float] = 60.0

# Max files the Patch Agent will inspect for a single vulnerability. Hard
# cap so a runaway code-search prompt cannot saturate the LLM call.
PATCH_MAX_CANDIDATE_FILES: Final[int] = 5
