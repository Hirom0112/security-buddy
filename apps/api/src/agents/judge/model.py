"""Pinned model and decoding parameters for the Judge agent.

CLAUDE.md §6 — The Judge is the platform's measurement instrument. It cannot
drift silently. These constants are **hardcoded**, not configured via env, not
exposed as a feature flag. Changing any value here requires:

  1. A code commit (this file is touched).
  2. A recorded eval baseline diff in docs/EVAL_BASELINES.md — both the
     old accuracy and the new must appear in the PR description.

Why not a config file: drift detection. A config value can be changed silently
in an env-var update; a code change forces a diff in review.

The rubric_version string is appended to each verdicts row so that a future
regression run on a frozen vulnerability uses the rubric the verdict was
made under, not the current rubric (CLAUDE.md §6a).
"""

from typing import Final

# OpenRouter model identifier. Anthropic's claude-sonnet-4-6 is the latest
# Sonnet at time of pinning. The full identifier is what OpenRouter expects.
JUDGE_MODEL: Final[str] = "anthropic/claude-sonnet-4.6"

# Temperature 0 is non-negotiable: the Judge must be deterministic enough for
# eval reproducibility. CLAUDE.md §6 — "Temperature is 0. Always."
JUDGE_TEMPERATURE: Final[float] = 0.0

# Rubric version string. Bump on any prompt or rubric-shape change.
# Persisted to verdicts.rubric_version and (later) snapshotted into
# vulnerabilities.rubric_snapshot so regression runs replay against the
# rubric the original verdict was made under.
JUDGE_RUBRIC_VERSION: Final[str] = "judge-rubric-v1"

# Agent tag for llm_client cost attribution (CLAUDE.md §"LLM call logging").
JUDGE_AGENT_TAG: Final[str] = "judge"
