"""Pinned model + decoding for the Documentation Agent.

CLAUDE.md §6 pins the Judge specifically. The Documentation Agent is held to
a softer bar (its output is read by humans, not used for measurement) but we
still hard-code the model and temperature here so a `git blame` line is
always available and the eval baseline is reproducible.
"""

from typing import Final

DOCUMENTATION_MODEL: Final[str] = "anthropic/claude-sonnet-4.6"
DOCUMENTATION_TEMPERATURE: Final[float] = 0.0
DOCUMENTATION_AGENT_TAG: Final[str] = "documentation"

# Wall-clock timeout for the report-generator LLM call. The Documentation
# Agent runs asynchronously after a verdict; a slow call is annoying, not
# critical. Beyond this we treat the call as failed and write a draft with
# a parse_failure note.
DOCUMENTATION_LLM_TIMEOUT_SECONDS: Final[float] = 45.0
