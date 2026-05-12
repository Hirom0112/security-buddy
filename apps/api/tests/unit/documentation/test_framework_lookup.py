"""Framework citation resolver — strict, no LLM-supplied IDs."""

import pytest

from src.agents.documentation.framework_lookup import (
    FrameworkLookupError,
    resolve_citation,
)


def _mappings() -> dict[str, object]:
    return {
        "owasp_llm": "LLM01:2025",
        "mitre_atlas": "AML.T0051.001",
        "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
    }


def _versions() -> dict[str, object]:
    return {
        "owasp_llm": "2025-v2.0",
        "mitre_atlas": "5.1.0",
        "hipaa": "2013-omnibus",
    }


def test_resolve_happy_path() -> None:
    c = resolve_citation(
        framework_mappings=_mappings(),
        framework_versions=_versions(),
    )
    assert c.owasp_llm_id == "LLM01:2025"
    assert c.mitre_atlas_technique_id == "AML.T0051.001"
    assert c.hipaa_safeguard == "164.312(a)(1), 164.312(c)(1)"
    assert c.framework_versions == {
        "owasp_llm": "2025-v2.0",
        "mitre_atlas": "5.1.0",
        "hipaa": "2013-omnibus",
    }


def test_hipaa_as_single_string() -> None:
    m = _mappings()
    m["hipaa"] = "164.308(a)(1)"
    c = resolve_citation(framework_mappings=m, framework_versions=_versions())
    assert c.hipaa_safeguard == "164.308(a)(1)"


def test_missing_owasp_raises() -> None:
    m = _mappings()
    del m["owasp_llm"]
    with pytest.raises(FrameworkLookupError, match="owasp"):
        resolve_citation(framework_mappings=m, framework_versions=_versions())


def test_missing_atlas_raises() -> None:
    m = _mappings()
    del m["mitre_atlas"]
    with pytest.raises(FrameworkLookupError, match="atlas"):
        resolve_citation(framework_mappings=m, framework_versions=_versions())


def test_empty_hipaa_raises() -> None:
    m = _mappings()
    m["hipaa"] = []
    with pytest.raises(FrameworkLookupError, match="hipaa"):
        resolve_citation(framework_mappings=m, framework_versions=_versions())


def test_blank_owasp_raises() -> None:
    m = _mappings()
    m["owasp_llm"] = "   "
    with pytest.raises(FrameworkLookupError):
        resolve_citation(framework_mappings=m, framework_versions=_versions())


def test_versions_missing_raises() -> None:
    with pytest.raises(FrameworkLookupError, match="framework_versions"):
        resolve_citation(framework_mappings=_mappings(), framework_versions={})


def test_versions_are_stringified() -> None:
    c = resolve_citation(
        framework_mappings=_mappings(),
        framework_versions={"owasp_llm": "2025-v2.0", "year": 2025},  # type: ignore[dict-item]
    )
    assert c.framework_versions["year"] == "2025"
