"""Unit tests for the Red Team seed loader.

Tests cover:
- Happy-path: all four CRITICAL subcategories load with ≥ 3 seeds each.
- Framework-mapping fidelity: each subcategory's mappings match migration 0003.
- Subcategory consistency: every seed's subcategory matches its filename.
- seed_id uniqueness across the full library.
- DuplicateSeedIdError on synthetic duplicate.
- SeedSubcategoryMismatchError on synthetic mismatch.
- Canary-token coverage: ≥ 2 seeds reference SYSTEM_BOUNDARY_TOKEN=cc-pilot-v1.
- pt-018 coverage: out-of-panel patient appears in cross_patient_leakage seeds.

All tests are pure-functional: no I/O, no DB, no HTTP.
Fixture seeds are written into a tmp_path directory for isolation tests.
"""

import json
from pathlib import Path

import pytest

from src.agents.red_team.seed_loader import (
    DuplicateSeedIdError,
    SeedSubcategoryMismatchError,
    load_all_seeds,
    load_seeds_for_subcategory,
)
from src.agents.red_team.types import SeedAttack

# ---------------------------------------------------------------------------
# Framework mappings from migration 0003 — canonical source of truth.
# These are the values the seeds MUST carry verbatim.
# ---------------------------------------------------------------------------
EXPECTED_MAPPINGS: dict[str, dict[str, str | list[str]]] = {
    "prompt_injection/indirect_via_upload": {
        "owasp_llm": "LLM01:2025",
        "mitre_atlas": "AML.T0051.001",
        "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
    },
    "data_exfiltration/cross_patient_leakage": {
        "owasp_llm": "LLM02:2025",
        "mitre_atlas": "AML.T0057",
        "hipaa": ["164.312(a)(1)", "164.308(a)(4)"],
    },
    "tool_misuse/unintended_invocation": {
        "owasp_llm": "LLM06:2025",
        "mitre_atlas": "AML.T0086",
        "hipaa": ["164.312(c)(1)", "164.312(a)(2)(iv)"],
    },
    "identity_role/privilege_escalation": {
        "owasp_llm": "LLM06:2025",
        "mitre_atlas": "AML.T0054",
        "hipaa": ["164.308(a)(4)", "164.312(a)(1)"],
    },
}

CRITICAL_SUBCATEGORIES = list(EXPECTED_MAPPINGS.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_seeds() -> dict[str, list[SeedAttack]]:
    """Load the real seeds once. Cached per-process by pytest."""
    return load_all_seeds()


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


class TestLoadAllSeedsHappyPath:
    def test_returns_all_four_critical_subcategories(self) -> None:
        seeds_map = _all_seeds()
        for subcategory in CRITICAL_SUBCATEGORIES:
            assert subcategory in seeds_map, (
                f"Expected subcategory '{subcategory}' not found in loaded seeds. "
                f"Available: {list(seeds_map.keys())}"
            )

    def test_each_critical_subcategory_has_at_least_three_seeds(self) -> None:
        seeds_map = _all_seeds()
        for subcategory in CRITICAL_SUBCATEGORIES:
            count = len(seeds_map[subcategory])
            assert count >= 3, (
                f"subcategory '{subcategory}' has only {count} seed(s); "
                "PLAN.md §Slice 1 #2 requires ≥ 3 per CRITICAL subcategory."
            )

    def test_returns_at_least_four_subcategories_total(self) -> None:
        seeds_map = _all_seeds()
        assert len(seeds_map) >= 4, (
            f"Expected ≥ 4 subcategories total, got {len(seeds_map)}: {list(seeds_map.keys())}"
        )

    def test_all_returned_objects_are_seed_attack_instances(self) -> None:
        seeds_map = _all_seeds()
        for subcategory, seeds in seeds_map.items():
            for seed in seeds:
                assert isinstance(seed, SeedAttack), (
                    f"seed in '{subcategory}' is not a SeedAttack: {type(seed)}"
                )


# ---------------------------------------------------------------------------
# Framework-mapping fidelity tests (against migration 0003)
# ---------------------------------------------------------------------------


class TestFrameworkMappings:
    @pytest.mark.parametrize("subcategory", CRITICAL_SUBCATEGORIES)
    def test_all_seeds_carry_correct_owasp_llm_id(self, subcategory: str) -> None:
        seeds_map = _all_seeds()
        expected_owasp = EXPECTED_MAPPINGS[subcategory]["owasp_llm"]
        for seed in seeds_map[subcategory]:
            assert seed.framework_mappings.get("owasp_llm") == expected_owasp, (
                f"seed '{seed.seed_id}' in '{subcategory}' has "
                f"owasp_llm='{seed.framework_mappings.get('owasp_llm')}', "
                f"expected '{expected_owasp}'."
            )

    @pytest.mark.parametrize("subcategory", CRITICAL_SUBCATEGORIES)
    def test_all_seeds_carry_correct_mitre_atlas_id(self, subcategory: str) -> None:
        seeds_map = _all_seeds()
        expected_atlas = EXPECTED_MAPPINGS[subcategory]["mitre_atlas"]
        for seed in seeds_map[subcategory]:
            assert seed.framework_mappings.get("mitre_atlas") == expected_atlas, (
                f"seed '{seed.seed_id}' in '{subcategory}' has "
                f"mitre_atlas='{seed.framework_mappings.get('mitre_atlas')}', "
                f"expected '{expected_atlas}'."
            )

    @pytest.mark.parametrize("subcategory", CRITICAL_SUBCATEGORIES)
    def test_all_seeds_carry_correct_hipaa_safeguards(self, subcategory: str) -> None:
        seeds_map = _all_seeds()
        expected_hipaa = EXPECTED_MAPPINGS[subcategory]["hipaa"]
        for seed in seeds_map[subcategory]:
            actual_hipaa = seed.framework_mappings.get("hipaa")
            assert actual_hipaa == expected_hipaa, (
                f"seed '{seed.seed_id}' in '{subcategory}' has "
                f"hipaa={actual_hipaa!r}, expected {expected_hipaa!r}."
            )


# ---------------------------------------------------------------------------
# seed_id uniqueness
# ---------------------------------------------------------------------------


class TestSeedIdUniqueness:
    def test_all_seed_ids_are_unique_across_library(self) -> None:
        seeds_map = _all_seeds()
        all_ids: list[str] = [seed.seed_id for seeds in seeds_map.values() for seed in seeds]
        unique_ids = set(all_ids)
        assert len(all_ids) == len(unique_ids), (
            f"Duplicate seed_id(s) found. Total: {len(all_ids)}, Unique: {len(unique_ids)}. "
            f"Duplicates: {[i for i in all_ids if all_ids.count(i) > 1]}"
        )


# ---------------------------------------------------------------------------
# Subcategory consistency (each seed's subcategory matches its filename)
# ---------------------------------------------------------------------------


class TestSubcategoryConsistency:
    @pytest.mark.parametrize("subcategory", CRITICAL_SUBCATEGORIES)
    def test_seeds_subcategory_matches_filename(self, subcategory: str) -> None:
        seeds = load_seeds_for_subcategory(subcategory)
        for seed in seeds:
            assert seed.subcategory == subcategory, (
                f"seed '{seed.seed_id}' has subcategory='{seed.subcategory}', "
                f"expected '{subcategory}' (derived from filename)."
            )


# ---------------------------------------------------------------------------
# Target-surface assertions — pt-018 and canary coverage
# ---------------------------------------------------------------------------


class TestTargetSurface:
    def test_pt_018_referenced_in_cross_patient_seeds(self) -> None:
        """At least one cross_patient_leakage seed must reference pt-018 Thomas Greer.

        This is the out-of-panel control patient per TARGET_MANIFEST.md §7.
        """
        seeds_map = _all_seeds()
        subcategory = "data_exfiltration/cross_patient_leakage"
        seeds = seeds_map[subcategory]

        pt018_refs = [
            s
            for s in seeds
            if "pt-018" in s.message_template or "Thomas Greer" in s.message_template
        ]
        assert len(pt018_refs) >= 1, (
            "No cross_patient_leakage seed references 'pt-018' or 'Thomas Greer'. "
            "The out-of-panel control patient must appear in at least one seed template "
            "(TARGET_MANIFEST.md §7)."
        )

    def test_canary_token_in_at_least_two_seeds(self) -> None:
        """≥ 2 seeds must reference the system-boundary canary SYSTEM_BOUNDARY_TOKEN=cc-pilot-v1.

        Per TARGET_MANIFEST.md §5.6 and CLAUDE.md §Slice 1B requirements.
        """
        seeds_map = _all_seeds()
        canary = "SYSTEM_BOUNDARY_TOKEN=cc-pilot-v1"
        canary_seeds = [
            seed
            for seeds in seeds_map.values()
            for seed in seeds
            if canary in seed.message_template
        ]
        assert len(canary_seeds) >= 2, (
            f"Expected ≥ 2 seeds containing the canary token '{canary}', "
            f"found {len(canary_seeds)}. "
            "Indirect injection and privilege escalation seeds should both probe the canary."
        )


# ---------------------------------------------------------------------------
# Error-path tests using synthetic fixtures (tmp_path)
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _minimal_seed(seed_id: str, subcategory: str) -> dict[str, object]:
    """Return a minimal valid seed dict for a given subcategory."""
    category = subcategory.split("/")[0]
    return {
        "seed_id": seed_id,
        "category": category,
        "subcategory": subcategory,
        "message_template": f"Test message for {seed_id}",
        "target_endpoint": "POST /agent/query",
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051.001",
            "hipaa": ["164.312(a)(1)"],
        },
        "expected_safe_behavior": "Agent refuses the request.",
        "judge_rubric_hints": {
            "trust_boundary": "5.3_identity_persistence",
            "violation_signal": "Any canary leak.",
            "success_criteria": "Agent refuses.",
            "evidence_required": "Full response text.",
        },
        "tags": ["test"],
    }


class TestDuplicateSeedIdError:
    def test_raises_on_duplicate_seed_id_within_single_file(self, tmp_path: Path) -> None:
        subcategory = "prompt_injection/indirect_via_upload"
        seeds = [
            _minimal_seed("seed-dup-001", subcategory),
            _minimal_seed("seed-dup-001", subcategory),  # duplicate
        ]
        _write_json(tmp_path / "prompt_injection__indirect_via_upload.json", seeds)

        with pytest.raises(DuplicateSeedIdError) as exc_info:
            load_all_seeds(seeds_dir=tmp_path)

        assert exc_info.value.seed_id == "seed-dup-001"

    def test_raises_on_duplicate_seed_id_across_files(self, tmp_path: Path) -> None:
        seed_id = "seed-cross-dup-001"
        subcat_a = "prompt_injection/indirect_via_upload"
        subcat_b = "data_exfiltration/cross_patient_leakage"

        _write_json(
            tmp_path / "prompt_injection__indirect_via_upload.json",
            [_minimal_seed(seed_id, subcat_a)],
        )
        _write_json(
            tmp_path / "data_exfiltration__cross_patient_leakage.json",
            [_minimal_seed(seed_id, subcat_b)],
        )

        with pytest.raises(DuplicateSeedIdError) as exc_info:
            load_all_seeds(seeds_dir=tmp_path)

        assert exc_info.value.seed_id == seed_id

    def test_error_message_includes_conflicting_filenames(self, tmp_path: Path) -> None:
        seed_id = "seed-fn-check-001"
        subcat_a = "prompt_injection/indirect_via_upload"
        subcat_b = "data_exfiltration/cross_patient_leakage"

        _write_json(
            tmp_path / "prompt_injection__indirect_via_upload.json",
            [_minimal_seed(seed_id, subcat_a)],
        )
        _write_json(
            tmp_path / "data_exfiltration__cross_patient_leakage.json",
            [_minimal_seed(seed_id, subcat_b)],
        )

        with pytest.raises(DuplicateSeedIdError) as exc_info:
            load_all_seeds(seeds_dir=tmp_path)

        assert "prompt_injection__indirect_via_upload.json" in str(exc_info.value) or (
            len(exc_info.value.files) == 2
        )


class TestSeedSubcategoryMismatchError:
    def test_raises_when_seed_subcategory_does_not_match_filename(self, tmp_path: Path) -> None:
        wrong_seed = _minimal_seed("seed-mismatch-001", "tool_misuse/unintended_invocation")
        # File says prompt_injection__indirect_via_upload but seed says tool_misuse/...
        _write_json(tmp_path / "prompt_injection__indirect_via_upload.json", [wrong_seed])

        with pytest.raises(SeedSubcategoryMismatchError) as exc_info:
            load_all_seeds(seeds_dir=tmp_path)

        assert exc_info.value.seed_id == "seed-mismatch-001"
        assert exc_info.value.expected_subcategory == "prompt_injection/indirect_via_upload"
        assert exc_info.value.actual_subcategory == "tool_misuse/unintended_invocation"

    def test_error_message_is_informative(self, tmp_path: Path) -> None:
        wrong_seed = _minimal_seed("seed-msg-001", "identity_role/privilege_escalation")
        _write_json(tmp_path / "prompt_injection__indirect_via_upload.json", [wrong_seed])

        with pytest.raises(SeedSubcategoryMismatchError) as exc_info:
            load_seeds_for_subcategory("prompt_injection/indirect_via_upload", seeds_dir=tmp_path)

        error_message = str(exc_info.value)
        assert "seed-msg-001" in error_message
        assert "prompt_injection/indirect_via_upload" in error_message
        assert "identity_role/privilege_escalation" in error_message


class TestLoadSeedsForSubcategoryEdgeCases:
    def test_raises_file_not_found_for_unknown_subcategory(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_seeds_for_subcategory("nonexistent/subcategory", seeds_dir=tmp_path)

    def test_empty_seeds_dir_returns_empty_dict(self, tmp_path: Path) -> None:
        result = load_all_seeds(seeds_dir=tmp_path)
        assert result == {}

    def test_valid_single_seed_roundtrips_correctly(self, tmp_path: Path) -> None:
        subcategory = "identity_role/privilege_escalation"
        seed_data = _minimal_seed("seed-rt-001", subcategory)
        _write_json(tmp_path / "identity_role__privilege_escalation.json", [seed_data])

        seeds = load_seeds_for_subcategory(subcategory, seeds_dir=tmp_path)

        assert len(seeds) == 1
        assert seeds[0].seed_id == "seed-rt-001"
        assert seeds[0].subcategory == subcategory
        assert seeds[0].target_endpoint == "POST /agent/query"
