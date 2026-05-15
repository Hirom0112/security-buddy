# Eval Dataset

This directory is the **submission-spec pointer**. The actual eval ground-truth sets, runners, and result history live alongside the API code at [`apps/api/tests/evals/`](../apps/api/tests/evals/) so they ship in the same Python package as the agents they evaluate. Recorded baselines for every run are in [`docs/EVAL_BASELINES.md`](../docs/EVAL_BASELINES.md).

## What's evaluated

Three independent LLM components have ground-truth eval suites, each covering ≥4 attack categories per CLAUDE.md §1 ("Evals for LLM Code"):

| Component | Ground truth | Runner | Baseline |
|---|---|---|---|
| **Judge** (verdict adjudication + `data_actually_disclosed` field) | [`apps/api/tests/evals/judge_ground_truth.jsonl`](../apps/api/tests/evals/judge_ground_truth.jsonl) — **40 hand-labeled rows** across the 4 CRITICAL subcategories: `prompt_injection/indirect_via_upload`, `data_exfiltration/cross_patient_leakage`, `tool_misuse/unintended_invocation`, `identity_role/privilege_escalation` | [`run_judge_eval.py`](../apps/api/tests/evals/run_judge_eval.py) | **0.825 verdict accuracy (33/40)**, exploit class P/R **1.00 / 1.00**, disclosure axis **0.895** ([`EVAL_BASELINES.md`](../docs/EVAL_BASELINES.md)) |
| **Documentation Agent** (report quality + framework-citation correctness) | [`apps/api/tests/evals/documentation_ground_truth.jsonl`](../apps/api/tests/evals/documentation_ground_truth.jsonl) | [`run_documentation_eval.py`](../apps/api/tests/evals/run_documentation_eval.py) | **0.8167 composite** ([`EVAL_BASELINES.md`](../docs/EVAL_BASELINES.md)) |
| **Red Team** (mutation diversity + novelty against refused responses) | [`apps/api/tests/evals/red_team_ground_truth.jsonl`](../apps/api/tests/evals/red_team_ground_truth.jsonl) — 15 rows across all 4 CRITICAL subcategories | [`run_red_team_eval.py`](../apps/api/tests/evals/run_red_team_eval.py) | _pending operator's first run_ |

Result JSONs from every run are archived in [`apps/api/tests/evals/results/`](../apps/api/tests/evals/results/) keyed by git SHA.

## Reproducing the baselines

Reproducibility is the whole point. Every result JSON committed includes the git SHA it was run against, the model string, the cost per call, and per-row pass/fail — anyone can re-run and diff.

```bash
# One-time setup
cd apps/api
uv sync

# Run any eval (each costs ~$0.30 in OpenRouter credits)
export OPENROUTER_API_KEY=...
export LANGSMITH_API_KEY=...            # or "DISABLED"
export LANGSMITH_PROJECT=security-buddy
export DATABASE_URL=postgresql+asyncpg://placeholder/placeholder
export REDIS_URL=redis://placeholder:6379
export SESSION_SECRET=placeholder-session-secret-placeholder-placeholder

uv run python tests/evals/run_judge_eval.py            # 40 rows, ~$0.32
uv run python tests/evals/run_documentation_eval.py    # 5 rows
uv run python tests/evals/run_red_team_eval.py         # 15 rows
```

Each runner writes `tests/evals/results/<component>_<sha>.json`. Diff against the committed baselines in [`docs/EVAL_BASELINES.md`](../docs/EVAL_BASELINES.md).

## Why three separate evals, not one

Per CLAUDE.md §1: LLM-driven code follows an **eval-first pattern** where a baseline must exist before the component ships. Each agent has its own measurement instrument because what counts as "correct" differs:

- **Judge** is a classifier — accuracy + per-class P/R + a new `data_actually_disclosed` accuracy axis added in commit `b839300` to address operator-reported over-calling (auth-bypass-but-empty-response was being labeled CRITICAL alongside real PHI leaks).
- **Documentation Agent** is a generator scored on report structure: reproduction steps complete? severity correct? framework citations (OWASP / MITRE / HIPAA) match the source subcategory in `attack_taxonomy`?
- **Red Team** is a generator scored on mutation novelty (SequenceMatcher distance from seed > 0.5) and diversity (covers ≥2 expected mutation categories per ground-truth row).

## CI integration

Evals do **not** run on every commit (they cost money and depend on a live API). Each has a manual-trigger GitHub Actions workflow under [`.github/workflows/`](../.github/workflows/): `judge-eval.yml`, `documentation-eval.yml`, `red-team-eval.yml`. The Judge workflow fails the run when accuracy drops below 0.85 — same threshold used at the CLI.
