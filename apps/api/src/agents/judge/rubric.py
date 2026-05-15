"""Rubric resolution — pure function from manifest + brief to a Rubric.

Pulled out of the LangGraph node so it is unit-testable without an event loop
or any LLM/DB dependency. The node simply hydrates inputs from Postgres and
hands them here.
"""

from typing import Any

from src.agents.judge.schema import Rubric, TrustBoundary


class RubricResolutionError(ValueError):
    """Raised when the manifest is missing required keys.

    A missing trust_boundaries or expected_safe_behaviors_by_subcategory is a
    seed-time configuration bug — surface it loudly rather than judging with
    an empty rubric.
    """


def resolve_rubric(
    *,
    manifest_json: dict[str, Any],
    subcategory: str,
    success_criteria: dict[str, object],
) -> Rubric:
    """Compose the Rubric the Judge prompt will read for this attack.

    Args:
        manifest_json: target_manifests.manifest_json blob.
        subcategory: attacks.subcategory (e.g. "prompt_injection/indirect_via_upload").
        success_criteria: campaign_briefs.success_criteria JSONB.

    Returns:
        Frozen Rubric ready to render into the prompt.

    Raises:
        RubricResolutionError: if manifest is missing trust_boundaries or
            does not specify expected_safe_behavior for this subcategory.
    """
    raw_boundaries = manifest_json.get("trust_boundaries")
    if not isinstance(raw_boundaries, list) or not raw_boundaries:
        raise RubricResolutionError("manifest_json.trust_boundaries is missing or empty")

    boundaries = [TrustBoundary.model_validate(b) for b in raw_boundaries]

    behaviors = manifest_json.get("expected_safe_behaviors_by_subcategory", {})
    if not isinstance(behaviors, dict):
        raise RubricResolutionError(
            "manifest_json.expected_safe_behaviors_by_subcategory must be a dict"
        )

    expected_safe = behaviors.get(subcategory)
    if not isinstance(expected_safe, str) or not expected_safe.strip():
        raise RubricResolutionError(
            f"No expected_safe_behavior recorded for subcategory '{subcategory}'"
        )

    return Rubric(
        subcategory=subcategory,
        trust_boundaries=boundaries,
        expected_safe_behavior=expected_safe,
        success_criteria=success_criteria,
    )
