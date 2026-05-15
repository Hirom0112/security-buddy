"""Documentation Agent quality eval.

Five hand-authored exploit fixtures with expected severity + reproduction
topics + remediation topics. The runner calls the live Sonnet prompt,
parses the draft, and scores four dimensions:

  severity_correctness     1.0 if predicted_severity == expected_severity,
                           0.5 if within one rank, else 0.0
  reproduction_completeness fraction of `reproduction_must_include` tokens
                           that appear in reproduction_steps
  remediation_presence     fraction of `must_remediate_topics` that appear
                           anywhere in remediation_or_recommended_text
  framework_citation_accuracy  1.0 if the deterministic citation matches
                           the source subcategory's attack_taxonomy row;
                           0.0 if it diverges. (Always 1.0 if the worker
                           pipeline is intact — the LLM never supplies
                           framework IDs, but we check anyway as a guard
                           against accidental drift in framework_lookup.)

Average of the four per row is the row's score. The eval baseline is the
average score across the fixture set. Threshold default 0.80.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_API_ROOT = _HERE.parent.parent
sys.path.insert(0, str(_API_ROOT))

from src.agents.documentation.framework_lookup import resolve_citation  # noqa: E402
from src.agents.documentation.model import (  # noqa: E402
    DOCUMENTATION_AGENT_TAG,
    DOCUMENTATION_MODEL,
)
from src.agents.documentation.parse import (  # noqa: E402
    DocumentationParseError,
    parse_draft,
)
from src.agents.documentation.prompt import build_documentation_messages  # noqa: E402
from src.llm_client.client import LLMClient  # noqa: E402
from src.settings import get_settings  # noqa: E402

_FIXTURES_PATH = _HERE / "documentation_fixtures.jsonl"
_RESULTS_DIR = _HERE / "results"

# Snapshot of the taxonomy rows we need so the eval doesn't touch Postgres.
# Keep in sync with apps/api/alembic/versions/0003_seed_attack_taxonomy.py.
_TAXONOMY_FRAGMENT: dict[str, dict[str, Any]] = {
    "data_exfiltration/cross_patient_leakage": {
        "mappings": {
            "owasp_llm": "LLM06:2025",
            "mitre_atlas": "AML.T0048",
            "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
        },
        "versions": {
            "owasp_llm": "2025-v2.0",
            "mitre_atlas": "5.1.0",
            "hipaa": "2013-omnibus",
        },
    },
    "prompt_injection/indirect_via_upload": {
        "mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051.001",
            "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
        },
        "versions": {
            "owasp_llm": "2025-v2.0",
            "mitre_atlas": "5.1.0",
            "hipaa": "2013-omnibus",
        },
    },
    "tool_misuse/unintended_invocation": {
        "mappings": {
            "owasp_llm": "LLM06:2025",
            "mitre_atlas": "AML.T0053",
            "hipaa": ["164.308(a)(1)"],
        },
        "versions": {
            "owasp_llm": "2025-v2.0",
            "mitre_atlas": "5.1.0",
            "hipaa": "2013-omnibus",
        },
    },
    "identity_role/privilege_escalation": {
        "mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0054",
            "hipaa": ["164.308(a)(3)"],
        },
        "versions": {
            "owasp_llm": "2025-v2.0",
            "mitre_atlas": "5.1.0",
            "hipaa": "2013-omnibus",
        },
    },
}


@dataclass
class RowResult:
    id: str
    subcategory: str
    expected_severity: str
    predicted_severity: str | None
    severity_correctness: float
    reproduction_completeness: float
    remediation_presence: float
    framework_citation_accuracy: float
    composite: float
    cost_usd: float
    parse_failed: bool


def _git_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_API_ROOT,
            stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _severity_score(predicted: str, expected: str) -> float:
    if predicted == expected:
        return 1.0
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    p = rank.get(predicted, 0)
    e = rank.get(expected, 0)
    return 0.5 if abs(p - e) == 1 else 0.0


def _topic_coverage(text: str, must: list[str]) -> float:
    if not must:
        return 1.0
    text_l = text.lower()
    hits = sum(1 for t in must if t.lower() in text_l)
    return hits / len(must)


async def _eval_one(client: LLMClient, fixture: dict[str, Any]) -> RowResult:
    sub = fixture["subcategory"]
    tax = _TAXONOMY_FRAGMENT.get(sub)
    if tax is None:
        raise RuntimeError(f"No taxonomy fragment for subcategory {sub!r}")

    citation = resolve_citation(
        framework_mappings=tax["mappings"],
        framework_versions=tax["versions"],
    )

    messages = build_documentation_messages(
        subcategory=sub,
        attack_input=fixture["attack_input"],
        target_response=fixture["target_response"],
        target_response_status=fixture.get("target_response_status"),
        verdict_evidence=fixture["verdict_evidence"],
        violated_boundary_ids=list(fixture.get("violated_boundary_ids") or []),
        citation=citation,
        expected_safe_behavior=None,
    )

    try:
        completion = await client.complete(
            model=DOCUMENTATION_MODEL,
            messages=messages,
            agent=DOCUMENTATION_AGENT_TAG,
        )
    except Exception:
        return RowResult(
            id=fixture["id"],
            subcategory=sub,
            expected_severity=fixture["expected_severity"],
            predicted_severity=None,
            severity_correctness=0.0,
            reproduction_completeness=0.0,
            remediation_presence=0.0,
            framework_citation_accuracy=1.0,
            composite=0.0,
            cost_usd=0.0,
            parse_failed=True,
        )

    try:
        draft = parse_draft(completion.content)
    except DocumentationParseError:
        return RowResult(
            id=fixture["id"],
            subcategory=sub,
            expected_severity=fixture["expected_severity"],
            predicted_severity=None,
            severity_correctness=0.0,
            reproduction_completeness=0.0,
            remediation_presence=0.0,
            framework_citation_accuracy=1.0,
            composite=0.0,
            cost_usd=completion.cost_usd,
            parse_failed=True,
        )

    predicted = draft.severity.value
    sev = _severity_score(predicted, fixture["expected_severity"])
    repro = _topic_coverage(
        draft.reproduction_steps, fixture.get("reproduction_must_include") or []
    )
    remediation_text = draft.recommended_remediation + " " + draft.expected_behavior
    rem = _topic_coverage(remediation_text, fixture.get("must_remediate_topics") or [])

    # Framework citation accuracy — the LLM never supplied IDs, but we
    # validate that resolve_citation produced the expected owasp_llm_id.
    expected_owasp = tax["mappings"]["owasp_llm"]
    fw_accuracy = 1.0 if citation.owasp_llm_id == expected_owasp else 0.0

    composite = (sev + repro + rem + fw_accuracy) / 4
    return RowResult(
        id=fixture["id"],
        subcategory=sub,
        expected_severity=fixture["expected_severity"],
        predicted_severity=predicted,
        severity_correctness=sev,
        reproduction_completeness=round(repro, 4),
        remediation_presence=round(rem, 4),
        framework_citation_accuracy=fw_accuracy,
        composite=round(composite, 4),
        cost_usd=completion.cost_usd,
        parse_failed=False,
    )


def _load_fixtures() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with _FIXTURES_PATH.open() as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


async def _run(threshold: float) -> int:
    fixtures = _load_fixtures()
    settings = get_settings()
    client = LLMClient(settings)

    results: list[RowResult] = []
    for i, fx in enumerate(fixtures, 1):
        r = await _eval_one(client, fx)
        results.append(r)
        marker = "OK " if r.composite >= threshold else "MISS"
        print(
            f"[{i}/{len(fixtures)}] {marker} {r.id} composite={r.composite} "
            f"sev={r.severity_correctness} repro={r.reproduction_completeness} "
            f"rem={r.remediation_presence} fw={r.framework_citation_accuracy} "
            f"cost=${r.cost_usd:.5f}"
        )

    avg = sum(r.composite for r in results) / len(results) if results else 0.0
    avg = round(avg, 4)
    total_cost = round(sum(r.cost_usd for r in results), 6)
    summary = {
        "git_sha": _git_sha(),
        "model": DOCUMENTATION_MODEL,
        "fixtures": len(results),
        "average_composite": avg,
        "total_cost_usd": total_cost,
        "parse_failures": sum(1 for r in results if r.parse_failed),
    }

    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _RESULTS_DIR / f"documentation_{summary['git_sha']}.json"
    out_path.write_text(
        json.dumps(
            {"summary": summary, "rows": [asdict(r) for r in results]},
            indent=2,
        )
    )

    print("\n" + "=" * 60)
    print(f"Average composite: {avg:.4f} (threshold {threshold:.2f})")
    print(f"Total cost: ${total_cost:.4f}")
    print(f"Results written to: {out_path.relative_to(_API_ROOT)}")
    print("=" * 60)

    if avg < threshold:
        print(f"FAIL — average {avg:.4f} below threshold {threshold:.2f}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Documentation Agent eval")
    parser.add_argument(
        "--threshold",
        type=float,
        default=float(os.environ.get("DOCUMENTATION_EVAL_THRESHOLD", "0.80")),
        help="Minimum required average composite score (default: 0.80)",
    )
    args = parser.parse_args()
    return asyncio.run(_run(args.threshold))


if __name__ == "__main__":
    raise SystemExit(main())
