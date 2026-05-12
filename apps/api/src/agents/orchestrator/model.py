"""Pinned model + decoding for the Orchestrator's brief generator.

The Orchestrator's LLM is strategic (framing the Layer-A choice) and runs
infrequently. It is **not** a measurement instrument — unlike the Judge,
its drift does not directly bias evaluation. Still, pin the model so cost
and behavior are reproducible across runs.

CLAUDE.md §6 explicitly pins the Judge. The Orchestrator is held to a
weaker bar (no eval baseline required), but we hard-code the model anyway
so a `git blame` line is always available.
"""

from typing import Final

ORCHESTRATOR_MODEL: Final[str] = "anthropic/claude-sonnet-4.6"
ORCHESTRATOR_TEMPERATURE: Final[float] = 0.2  # tiny spread for natural framing
ORCHESTRATOR_AGENT_TAG: Final[str] = "orchestrator"

# Wall-clock timeout for the brief-generator LLM call. Beyond this we fall
# back to the deterministic template — ARCHITECTURE.md §3.1 "Failure modes".
ORCHESTRATOR_LLM_TIMEOUT_SECONDS: Final[float] = 30.0
