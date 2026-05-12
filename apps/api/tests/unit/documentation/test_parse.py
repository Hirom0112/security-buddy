"""VulnerabilityDraft parser tests."""

import pytest

from src.agents.documentation.parse import (
    DocumentationParseError,
    parse_draft,
)
from src.agents.documentation.schema import Severity

_VALID = """{
    "title": "Cross-patient PHI leak via narrative containment breach",
    "severity": "critical",
    "clinical_impact": "An attacker on Sara Chen's session could pull pt-018 chart details by asking in natural language. The Co-Pilot's narrative names the out-of-panel patient and discloses CKD-stage information.",
    "reproduction_steps": "1. Authenticate as Sara Chen.\\n2. POST /agent/query with the recorded attack input.\\n3. Observe pt-018's name in the response narrative.",
    "observed_behavior": "Response narrative names pt-018 and reveals CKD stage.",
    "expected_behavior": "Boundary 5.1 / 5.2 should have caused the Co-Pilot to refuse with a generic message and not surface clinical content for the out-of-panel patient.",
    "recommended_remediation": "Add a post-generation containment filter that scrubs any patient_id not in session_context.patient_ids from the rendered narrative."
}"""


def test_parse_valid() -> None:
    draft = parse_draft(_VALID)
    assert draft.severity is Severity.CRITICAL
    assert "Cross-patient" in draft.title


def test_parse_fenced() -> None:
    fenced = f"```json\n{_VALID}\n```"
    draft = parse_draft(fenced)
    assert draft.severity is Severity.CRITICAL


def test_parse_empty_raises() -> None:
    with pytest.raises(DocumentationParseError):
        parse_draft("")


def test_parse_extra_fields_raises() -> None:
    bad = _VALID.replace(
        '"recommended_remediation":',
        '"unknown_field": "x", "recommended_remediation":',
    )
    with pytest.raises(DocumentationParseError):
        parse_draft(bad)


def test_parse_bad_severity_raises() -> None:
    bad = _VALID.replace('"severity": "critical"', '"severity": "extreme"')
    with pytest.raises(DocumentationParseError):
        parse_draft(bad)


def test_parse_short_title_raises() -> None:
    bad = _VALID.replace(
        '"title": "Cross-patient PHI leak via narrative containment breach"',
        '"title": "short"',
    )
    with pytest.raises(DocumentationParseError):
        parse_draft(bad)


def test_parse_no_json_object_raises() -> None:
    with pytest.raises(DocumentationParseError):
        parse_draft("I refuse to write this report.")


def test_parse_trailing_commentary() -> None:
    noisy = _VALID + "\n\nLet me know if you want changes."
    draft = parse_draft(noisy)
    assert draft.severity is Severity.CRITICAL
