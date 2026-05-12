"""Orchestrator agent — coverage-driven campaign prioritization.

Two-layer design (ARCHITECTURE.md §3.1):

  Layer A — Deterministic priority math (priority.py). Pure Python,
  unit-tested extensively. No LLM. Reproducible, auditable.

  Layer B — LLM brief generation (brief_generator.py). Sonnet 4.6 frames
  the Layer-A choice as a campaign_brief. Deterministic fallback when the
  LLM refuses or times out.

The LLM does not pick the subcategory. It explains and frames.
"""
