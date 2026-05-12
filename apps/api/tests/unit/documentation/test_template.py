"""Template renderer tests — framework IDs must always land in the title.

CLAUDE.md §6a: every report cites OWASP / MITRE / HIPAA. This is a
deterministic check, not LLM-judged.
"""

from src.agents.documentation.schema import (
    FrameworkCitation,
    Severity,
    VulnerabilityDraft,
)
from src.agents.documentation.template import render_markdown, render_title


def _draft() -> VulnerabilityDraft:
    return VulnerabilityDraft(
        title="Cross-patient PHI leak via panel containment breach",
        severity=Severity.CRITICAL,
        clinical_impact="x" * 50,
        reproduction_steps="1. step\n2. step\n3. step",
        observed_behavior="Response named pt-018 although out of panel.",
        expected_behavior="Refusal without naming the out-of-panel patient.",
        recommended_remediation="Add a post-generation containment filter scoped to the JWT panel.",
    )


def _citation() -> FrameworkCitation:
    return FrameworkCitation(
        owasp_llm_id="LLM06:2025",
        mitre_atlas_technique_id="AML.T0048",
        hipaa_safeguard="164.312(a)(1)",
        framework_versions={
            "owasp_llm": "2025-v2.0",
            "mitre_atlas": "5.1.0",
            "hipaa": "2013-omnibus",
        },
    )


def test_title_includes_all_three_framework_ids() -> None:
    title = render_title(draft=_draft(), citation=_citation())
    assert "LLM06:2025" in title
    assert "AML.T0048" in title
    assert "HIPAA §164.312(a)(1)" in title


def test_title_does_not_double_label_hipaa_prefix() -> None:
    c = _citation()
    c = c.model_copy(update={"hipaa_safeguard": "HIPAA §164.500"})
    title = render_title(draft=_draft(), citation=c)
    assert title.count("HIPAA") == 1


def test_markdown_includes_all_sections() -> None:
    md = render_markdown(
        vuln_id="VUL-0001",
        draft=_draft(),
        citation=_citation(),
        subcategory="data_exfiltration/cross_patient_leakage",
        final_severity=Severity.CRITICAL,
        target_version="v1.2.3",
    )
    for section in (
        "## Clinical Impact",
        "## Reproduction Steps",
        "## Observed Behavior",
        "## Expected Behavior",
        "## Recommended Remediation",
        "## Framework Versions Snapshot",
    ):
        assert section in md, f"missing section: {section}"


def test_markdown_remediation_references_framework_ids() -> None:
    """Slice 4 DoD: remediation section cites the framework IDs directly."""
    md = render_markdown(
        vuln_id="VUL-0001",
        draft=_draft(),
        citation=_citation(),
        subcategory="data_exfiltration/cross_patient_leakage",
        final_severity=Severity.CRITICAL,
        target_version=None,
    )
    # find the remediation section and verify framework IDs appear AFTER it.
    rem_idx = md.index("## Recommended Remediation")
    fw_idx = md.index("## Framework Versions Snapshot")
    middle = md[rem_idx:fw_idx]
    assert "LLM06:2025" in middle
    assert "AML.T0048" in middle
    assert "164.312(a)(1)" in middle


def test_markdown_includes_vuln_id_and_severity_badge() -> None:
    md = render_markdown(
        vuln_id="VUL-0042",
        draft=_draft(),
        citation=_citation(),
        subcategory="data_exfiltration/cross_patient_leakage",
        final_severity=Severity.CRITICAL,
        target_version=None,
    )
    assert "VUL-0042" in md
    assert "[CRITICAL]" in md


def test_markdown_includes_target_version_when_present() -> None:
    md = render_markdown(
        vuln_id="VUL-0001",
        draft=_draft(),
        citation=_citation(),
        subcategory="data_exfiltration/cross_patient_leakage",
        final_severity=Severity.HIGH,
        target_version="v3.0",
    )
    assert "**Target version:**" in md
    assert "v3.0" in md


def test_markdown_omits_target_version_when_absent() -> None:
    md = render_markdown(
        vuln_id="VUL-0001",
        draft=_draft(),
        citation=_citation(),
        subcategory="data_exfiltration/cross_patient_leakage",
        final_severity=Severity.HIGH,
        target_version=None,
    )
    assert "Target version" not in md


def test_render_is_deterministic() -> None:
    a = render_markdown(
        vuln_id="VUL-0001",
        draft=_draft(),
        citation=_citation(),
        subcategory="data_exfiltration/cross_patient_leakage",
        final_severity=Severity.CRITICAL,
        target_version=None,
    )
    b = render_markdown(
        vuln_id="VUL-0001",
        draft=_draft(),
        citation=_citation(),
        subcategory="data_exfiltration/cross_patient_leakage",
        final_severity=Severity.CRITICAL,
        target_version=None,
    )
    assert a == b
