"""The Judge's pinned constants — CLAUDE.md §6 guard tests.

These tests intentionally fail when someone changes the model, temperature,
or rubric version without thinking about the eval baseline. The tests are
the speed bump.
"""

from src.agents.judge import model


def test_model_is_pinned_to_claude_sonnet() -> None:
    """The Judge model must be a Claude Sonnet variant via OpenRouter.

    Changing this requires an eval baseline diff per CLAUDE.md §6.
    """
    assert model.JUDGE_MODEL.startswith("anthropic/claude-sonnet")


def test_temperature_is_zero() -> None:
    """CLAUDE.md §6: 'Temperature is 0. Always.'"""
    assert model.JUDGE_TEMPERATURE == 0.0


def test_rubric_version_is_set() -> None:
    """A non-empty rubric version is required so verdicts.rubric_version is meaningful."""
    assert isinstance(model.JUDGE_RUBRIC_VERSION, str)
    assert model.JUDGE_RUBRIC_VERSION.strip() != ""


def test_agent_tag_is_judge() -> None:
    """Cost attribution depends on agent='judge' tags in agent_traces."""
    assert model.JUDGE_AGENT_TAG == "judge"
