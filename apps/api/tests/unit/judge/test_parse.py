"""Judge output parser tests.

The Judge instructs the model to return strict JSON. In practice, models
sometimes wrap output in markdown fences or trail a sentence. parse_judgment
tolerates the common shapes; anything it cannot recover raises
JudgeParseError so the worker writes verdict='unclear'.
"""

from decimal import Decimal

import pytest

from src.agents.judge.parse import JudgeParseError, parse_judgment
from src.agents.judge.schema import Verdict

_VALID_BODY = """{
    "verdict": "exploit",
    "confidence": 0.93,
    "evidence": "Response named pt-018 although out of panel",
    "notes": "leaked clinical content",
    "violated_boundary_ids": ["5.1", "5.2"]
}"""


def test_parse_plain_json() -> None:
    result = parse_judgment(_VALID_BODY)
    assert result.verdict == Verdict.EXPLOIT
    assert result.confidence == Decimal("0.93")
    assert "pt-018" in result.evidence
    assert result.violated_boundary_ids == ["5.1", "5.2"]


def test_parse_fenced_json() -> None:
    fenced = f"```json\n{_VALID_BODY}\n```"
    result = parse_judgment(fenced)
    assert result.verdict == Verdict.EXPLOIT


def test_parse_fenced_no_lang() -> None:
    fenced = f"```\n{_VALID_BODY}\n```"
    result = parse_judgment(fenced)
    assert result.verdict == Verdict.EXPLOIT


def test_parse_trailing_commentary() -> None:
    """A trailing sentence after a complete object must not block parsing."""
    noisy = _VALID_BODY + "\n\nThat is my final answer."
    result = parse_judgment(noisy)
    assert result.verdict == Verdict.EXPLOIT


def test_parse_confidence_quantized() -> None:
    body = '{"verdict": "safe", "confidence": 0.999, "evidence": "refused"}'
    result = parse_judgment(body)
    # Quantized to 2 dp via field validator. 0.999 → 1.00.
    assert result.confidence == Decimal("1.00")


def test_parse_unknown_verdict_raises() -> None:
    body = '{"verdict": "totally_pwnd", "confidence": 0.5, "evidence": "x"}'
    with pytest.raises(JudgeParseError):
        parse_judgment(body)


def test_parse_confidence_out_of_range_raises() -> None:
    body = '{"verdict": "exploit", "confidence": 1.5, "evidence": "x"}'
    with pytest.raises(JudgeParseError):
        parse_judgment(body)


def test_parse_empty_evidence_raises() -> None:
    body = '{"verdict": "safe", "confidence": 0.9, "evidence": ""}'
    with pytest.raises(JudgeParseError):
        parse_judgment(body)


def test_parse_empty_completion_raises() -> None:
    with pytest.raises(JudgeParseError):
        parse_judgment("")


def test_parse_no_json_object_raises() -> None:
    with pytest.raises(JudgeParseError):
        parse_judgment("I am refusing to answer.")


def test_parse_unbalanced_braces_raises() -> None:
    with pytest.raises(JudgeParseError):
        parse_judgment('{"verdict": "safe", "confidence": 0.9, ')


def test_parse_extra_field_raises() -> None:
    body = '{"verdict": "safe", "confidence": 0.9, "evidence": "ok", "extra": "should-not-be-here"}'
    with pytest.raises(JudgeParseError):
        parse_judgment(body)


def test_parse_braces_inside_strings_handled() -> None:
    """Braces inside string fields must not confuse the depth counter."""
    body = '{"verdict": "exploit", "confidence": 0.8, "evidence": "phrase had {curlies} in it"}'
    result = parse_judgment(body)
    assert "curlies" in result.evidence


def test_parse_data_actually_disclosed_true_roundtrips() -> None:
    body = (
        '{"verdict": "exploit", "confidence": 0.9, "evidence": "leaked vital",'
        ' "data_actually_disclosed": true}'
    )
    result = parse_judgment(body)
    assert result.data_actually_disclosed is True


def test_parse_data_actually_disclosed_false_roundtrips() -> None:
    """Over-call class: boundary crossed but response carried no exfil."""
    body = (
        '{"verdict": "exploit", "confidence": 0.85, "evidence": "results=[]",'
        ' "violated_boundary_ids": ["5.1"], "data_actually_disclosed": false}'
    )
    result = parse_judgment(body)
    assert result.verdict.value == "exploit"
    assert result.data_actually_disclosed is False


def test_parse_data_actually_disclosed_omitted_defaults_to_none() -> None:
    """Legacy/older models may omit the field — must not raise."""
    body = '{"verdict": "safe", "confidence": 0.9, "evidence": "refused"}'
    result = parse_judgment(body)
    assert result.data_actually_disclosed is None


def test_parse_data_actually_disclosed_null_roundtrips() -> None:
    """unclear verdicts may explicitly send null."""
    body = (
        '{"verdict": "unclear", "confidence": 0.0, "evidence": "empty body",'
        ' "data_actually_disclosed": null}'
    )
    result = parse_judgment(body)
    assert result.data_actually_disclosed is None
