"""Patch-Agent prompt construction tests.

These tests pin the structural contract that downstream parsing depends on:
the file-selection prompt mentions the repo slug and asks for JSON; the
diff-generator prompt lists candidate paths, cites framework IDs, and
demands a 'Reviewer checklist' section.
"""

from __future__ import annotations

from src.agents.patch.prompt import (
    build_file_selection_messages,
    build_patch_draft_messages,
)


def test_file_selection_messages_include_repo_and_schema_hint() -> None:
    msgs = build_file_selection_messages(
        title="t",
        clinical_impact="ci",
        reproduction_steps="rs",
        observed_behavior="ob",
        expected_behavior="eb",
        recommended_remediation="rr",
        owasp_llm_id="LLM02",
        repo_slug="openemr-org/openemr",
    )
    assert len(msgs) == 2
    assert msgs[0].role == "system"
    assert "openemr-org/openemr" in msgs[0].content
    assert '"file_paths"' in msgs[0].content
    assert "LLM02" in msgs[1].content


def test_patch_draft_messages_list_candidates_and_require_checklist() -> None:
    msgs = build_patch_draft_messages(
        title="t",
        clinical_impact="ci",
        reproduction_steps="rs",
        recommended_remediation="rr",
        owasp_llm_id="LLM02",
        mitre_atlas_technique_id="AML.T0048",
        hipaa_safeguard="164.312(a)(1)",
        vuln_id="VUL-0001",
        repo_slug="openemr-org/openemr",
        candidate_paths=["src/a.py", "src/b.py"],
    )
    sys_msg = msgs[0].content
    user_msg = msgs[1].content
    assert "Reviewer checklist" in sys_msg
    assert "src/a.py" in user_msg
    assert "src/b.py" in user_msg
    assert "VUL-0001" in user_msg
    assert "AML.T0048" in user_msg
    assert "164.312(a)(1)" in user_msg


def test_patch_draft_messages_handle_zero_candidates() -> None:
    msgs = build_patch_draft_messages(
        title="t",
        clinical_impact="ci",
        reproduction_steps="rs",
        recommended_remediation="rr",
        owasp_llm_id="LLM02",
        mitre_atlas_technique_id="AML.T0048",
        hipaa_safeguard="164.312(a)(1)",
        vuln_id="VUL-0001",
        repo_slug="openemr-org/openemr",
        candidate_paths=[],
    )
    assert "(none)" in msgs[1].content
