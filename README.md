# Security Buddy

> A continuous adversarial evaluation platform for AI-assisted clinical
> workflows. Five agents — Orchestrator, Red Team, Judge, Documentation, Patch —
> work as one loop: discover vulnerabilities, document them, propose fixes, and
> verify the fixes held. Target: an OpenEMR Clinical Co-Pilot.

**Author:** Hirom Alarcon · **Week:** 3 — Gauntlet AI Austin Admission Track
**Status:** MVP loop verified end-to-end against a live deployed target on
2026-05-12 — see [Live Demo Results](#live-demo-results-2026-05-12) below.
Three curated critical findings exported to [`docs/findings/`](docs/findings/)
([VUL-0017](docs/findings/VUL-0017.md), [VUL-0021](docs/findings/VUL-0021.md),
[VUL-0023](docs/findings/VUL-0023.md)). Every report cites
**OWASP LLM Top 10 (2025)**, **MITRE ATLAS (v5.1.0)**, and the
**HIPAA Security Rule** (frameworks snapshotted at confirmation time per
`vulnerabilities.framework_versions`).

**Demo Video:** *[pending]*

**Architecture diagram:** See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §2
(System Diagram).

---

## For Graders — Submission Requirements Map

> **All graded documents live in [`docs/`](docs/).** Threat model, architecture,
> users, target manifest, plan, cost analysis, and vulnerability findings are
> all under that single directory. Direct links below.

Every required deliverable, with the exact path. Items marked *(in progress)*
are scheduled in [`docs/PLAN.md`](docs/PLAN.md) and will land before final
submission.

| Requirement | Location |
|---|---|
| **GitHub Repository** | This repo. See *Setup* and *Running Against the Live Target* below. |
| **Threat Model** (~500 word summary + full taxonomy) | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| **User Doc** (personas, workflows, automation justification) | [`docs/USERS.md`](docs/USERS.md) |
| **Architecture Doc** (~500 word summary + diagram + agents + regression harness + observability + tradeoffs) | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| **Target Manifest** (the target's contract — endpoints, auth, trust boundaries, expected safe behaviors; consumed by Red Team and Judge) | [`docs/TARGET_MANIFEST.md`](docs/TARGET_MANIFEST.md) |
| **Demo Video** (3–5 min, live attacks against the target) | *Recorded by operator separately; link appears here on submission.* |
| **Eval Dataset** (≥3 attack categories, reproducible) | [`evals/README.md`](evals/README.md) — orientation + reproducibility instructions. Three independent ground-truth sets (Judge 40 rows, Documentation 5 rows, Red Team 15 rows) live with the API at [`apps/api/tests/evals/`](apps/api/tests/evals/) so they ship with the agents they evaluate. Baselines tracked in [`docs/EVAL_BASELINES.md`](docs/EVAL_BASELINES.md). |
| **Vulnerability Reports** (≥3, professional format) | [`docs/findings/`](docs/findings/) — see [`docs/findings/README.md`](docs/findings/README.md) for the current state. A fresh Wide Sweep with the calibrated pipeline (disclosure gate + pre-write replay + dedup) is running now; three diverse-OWASP-category findings will be exported here on completion. Every report carries OWASP LLM 2025, MITRE ATLAS 5.1.0, and HIPAA Security Rule citations. |
| **AI Cost Analysis** (dev spend + projections at 100/1K/10K/100K runs) | [`docs/COST_ANALYSIS.md`](docs/COST_ANALYSIS.md) |
| **Deployed Application** (publicly accessible target, platform running live tests) | URLs in [§ Deployed URLs](#deployed-urls) below. First live campaign results in [§ Live Demo Results](#live-demo-results-2026-05-12). |

**Note on "Forked from OpenEMR".** The submission template assumes the platform
lives inside the target's fork. This project is architected differently and
intentionally so: Security Buddy is a **separate service** that attacks the
target only via its public HTTPS API, exactly as an external adversary would.
The Patch Agent has GitHub PR-author rights to a **separate** OpenEMR fork (no
shared infrastructure). See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §9
(Deployment Topology) and §5 (Trust Boundaries) for the full reasoning.

- **Platform repo (this one):** Security Buddy itself.
- **Target repo:** The OpenEMR fork the Patch Agent opens PRs against (built in
  Weeks 1–2). Link will be added to *Deployed URLs* below.

---

## What This Is

Security Buddy does not exist to find a single jailbreak. It exists to build,
over time, a defensible answer to a harder question: **is the target system
becoming more or less resilient as it evolves?**

The platform is five distinct agents, each with one role, each separated by
trust level, model class, and execution boundary:

1. **Orchestrator** (Claude Sonnet) — reads coverage state from Postgres,
   decides what to attack next using a deterministic priority function,
   enforces budgets, triggers regression runs when the target redeploys.
2. **Red Team** (open-weights Llama 70B via OpenRouter) — generates novel
   adversarial inputs and runs them live against the target. Open-weights by
   design — frontier models refuse offensive workflows unreliably.
3. **Judge** (Claude Sonnet, **pinned model, temperature 0**) — independent
   evaluation of every attack against a stored rubric. Different model class
   from the Red Team by design.
4. **Documentation Agent** (Claude Sonnet) — converts confirmed exploits into
   structured vulnerability reports with framework citations
   (OWASP LLM / MITRE ATLAS / HIPAA).
5. **Patch Agent** (Claude Sonnet) — proposes code fixes as pull requests
   against the target's fork. **Cannot merge** — branch protection enforces
   the human gate.

Agents do not message each other directly. **Postgres is the durable message
bus.** Every step is durable, replayable, idempotent on retry, and auditable
with a SQL query. Redis is ephemeral (worker queue, rate counters).

For the full picture — agent contracts, trust gradient, regression harness,
observability layer, framework versioning discipline — read
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). For the attack taxonomy with
OWASP LLM 2025 / MITRE ATLAS 5.1.0 / HIPAA mappings, read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Deployed URLs

All services live on Railway. Login required on the Security Buddy console
(single-operator auth, cookie-based).

- **Security Buddy (operator console):** https://security-buddy-production.up.railway.app
- **Security Buddy API:** https://security-buddy-api-production.up.railway.app
- **Target — OpenEMR Clinical Co-Pilot (chart system):** https://clinical-copilot-openemr-production.up.railway.app
- **Target — Agent-API (the AI surface being attacked):** https://copilot-agent-api-production.up.railway.app
- **Target repo (Patch Agent PR destination):** [`Hirom0112/openemr`](https://github.com/Hirom0112/openemr)
- **LangSmith trace project (all 5-agent traces, costs, timings):** [security-buddy](https://smith.langchain.com/o/10d059a6-56ff-46bc-b6a5-6d553b6bed67/projects/p/69f62167-2d7d-4f6f-81db-f631f8fd8c94)
  (GitHub PAT scoped to this fork only)

---

## Live Demo Results (2026-05-12)

The first end-to-end live campaign against the deployed Clinical Co-Pilot
produced:

| Metric | Value |
|---|---|
| Campaign | `60662d6c-5614-46f5-bf86-e4087a50df4a` |
| Attacks fired against live target | 18 |
| Verdicts written by Judge | 17 |
| **Exploits confirmed** | **13** (76% of judged attacks) |
| Partial findings | 2 |
| Safe responses | 2 |
| Vulnerability reports drafted by Documentation Agent | 13 (all critical, all `status='draft'`) |
| `agent_traces` rows (cost telemetry) | 44 |

12 critical findings remain in `status='draft'` — the soft-gate per
[`docs/USERS.md`](docs/USERS.md) pending operator confirmation. VUL-0008
(multi-patient handoff PHI leak) was confirmed on 2026-05-14: Patch Agent
opened PR #2 on `Hirom0112/openemr` (branch `security-buddy/vul-0008`,
+480/−2,973 lines, new `PatientAccessControlService.php`), operator reviewed
and merged, status now `proposed_fix`. Regression sweep pending.

> **Note (2026-05-15 update):** A second live campaign
> `ed26ea6b-71be-4c91-b7a4-75b0ac9a4476` ran after the LLM Red Team Agent
> shipped (commit `0772009`) — 20 attacks, 11 exploits, 10 critical drafts
> (VUL-0014..VUL-0023), $0.43 total. The three exported findings in
> [`docs/findings/`](docs/findings/) (VUL-0017, VUL-0021, VUL-0023) come from
> this later campaign. See [`docs/TODO.md`](docs/TODO.md) "Done 2026-05-14 —
> LLM Red Team live runs" for the full run log.

Eval baselines (recorded in [`docs/EVAL_BASELINES.md`](docs/EVAL_BASELINES.md)):

| Component | Threshold | Result |
|---|---|---|
| Judge accuracy | 0.85 | **0.875** (28/32 ground-truth cases) |
| Documentation composite | 0.80 | **0.817** (5/5 fixtures) |

Both above gate after a targeted prompt-engineering pass measured against
the ground-truth sets — see commit `634dd30` for the diff and
`EVAL_BASELINES.md` for before/after rows.

---

## Setup

Stack is locked. See [`CLAUDE.md`](CLAUDE.md) §"Technology Stack" for the full
list and rationale.

**Prerequisites:**

- Python 3.12+, [`uv`](https://github.com/astral-sh/uv)
- Node 20+, `pnpm`
- Docker + Docker Compose
- Accounts: OpenRouter, LangSmith, Railway, GitHub (with PAT scoped to the
  OpenEMR fork only)

**Local bring-up:**

```bash
# 1. Substrate
docker compose up -d                  # Postgres 16 + Redis 7

# 2. Backend
cd apps/api
uv sync
cp .env.example .env                  # fill in real values — no fallbacks
alembic upgrade head                  # creates schema + seeds attack_taxonomy
uvicorn src.main:app --reload         # http://localhost:8000

# 3. Worker (separate terminal)
cd apps/api
arq src.workers.WorkerSettings

# 4. Frontend (separate terminal)
cd apps/ui
cp .env.example .env.local
pnpm install
pnpm dev                              # http://localhost:3000
```

**Required environment variables** (no fallback defaults — missing values
cause startup failure):

```
# apps/api/.env
DATABASE_URL=postgresql+asyncpg://...
REDIS_URL=redis://localhost:6379
OPENROUTER_API_KEY=...
LANGSMITH_API_KEY=...
LANGSMITH_PROJECT=security-buddy
GITHUB_PAT=...                        # scoped to OpenEMR fork only
TARGET_BASE_URL=https://openemr.<your-domain>
TARGET_LOGIN_USER=...
TARGET_LOGIN_PASSWORD=...
SESSION_SECRET=...                    # for Security Buddy's own password gate
```

---

## Quick Start — Reproducing the Demo Loop End-to-End

The full discover → confirm → patch → verify loop, exactly as recorded in
the demo, runs against the live deployed target:

1. **Log in.** Open https://security-buddy-production.up.railway.app and
   authenticate with the operator password (single-user cookie session).
2. **Trigger a campaign.** From the dashboard, click **Start Campaign**, or
   POST to the API:

   ```bash
   curl -X POST https://security-buddy-api-production.up.railway.app/api/v1/campaigns/start \
     -H "Cookie: <session>" \
     -H "Content-Type: application/json" \
     -d '{"target_subcategory": "data_exfiltration/cross_patient_leakage", "budget_usd": 5.00}'
   ```

3. **Watch verdicts arrive.** The campaign detail page streams Judge verdicts
   live as the Red Team fires attacks at the deployed Co-Pilot. Each row shows
   the verdict (`exploit` / `partial` / `safe` / `unclear`), confidence, and
   rubric version.
4. **Confirm a critical finding.** Open `/vulnerabilities`, pick a draft
   CRITICAL finding (e.g., VUL-0017/0021/0023 from the exported set), review
   the Documentation Agent report (framework citations included), and confirm
   it. Confirming triggers the Patch Agent.
5. **See the PR.** The Patch Agent opens a branch and PR against
   [`Hirom0112/openemr`](https://github.com/Hirom0112/openemr). The PR link
   appears on the vulnerability page.
6. **Merge the PR.** Review the proposed fix on GitHub and merge. The merge
   webhook flips the vulnerability to `proposed_fix` and auto-enqueues a
   regression sweep.
7. **See the regression result.** Open `/vulnerabilities/[id]/diff` — the
   Before/After view shows the original exploit response on the left and the
   post-patch response on the right, with the frozen rubric verdict on each
   side. If the fix held, status moves to `resolved`.
8. **(Optional) Check spend.** `/cost` shows live LLM cost telemetry sourced
   from `agent_traces`, broken down per agent and per campaign.

All attacks against the target are rate-limited to **10 requests/second** and
capped at **1000 attacks per campaign**, enforced in the Red Team worker —
not in any LLM prompt (see [`CLAUDE.md`](CLAUDE.md) §"Critical Rules" §4).
The platform attacks only its configured target, authenticated as the
synthetic test persona `Sara Chen`. **All target data is synthetic — no real
PHI, ever.**

---

## Curated Findings

Three CRITICAL findings exported from live campaigns against the deployed
Clinical Co-Pilot. Each report includes the original prompt, the target's
response, Judge verdict + confidence, severity rationale, and framework
citations (OWASP LLM Top 10 2025 / MITRE ATLAS v5.1.0 / HIPAA Security Rule
§164.312) snapshotted at confirmation time:

- [`docs/findings/VUL-0017.md`](docs/findings/VUL-0017.md) — Out-of-panel
  patient record query executed without authorization check.
- [`docs/findings/VUL-0021.md`](docs/findings/VUL-0021.md) — Role-override
  prompt injection enables cross-patient medication data exfiltration.
- [`docs/findings/VUL-0023.md`](docs/findings/VUL-0023.md) — Lab results
  and vitals disclosed for out-of-panel patient without authorization.

---

## Testing

```bash
# Backend
cd apps/api
pytest                                # unit + integration
pytest tests/unit                     # unit only (fast)
pytest tests/evals --eval             # LLM evals (slow, costs money)
ruff check . && mypy src && lint-imports

# Frontend
cd apps/ui
pnpm typecheck && pnpm lint && pnpm test
pnpm test:e2e                         # Playwright end-to-end
```

The Judge is the platform's measurement instrument. Any change to its prompt,
model, or rubric handling requires a re-baselined ground-truth eval — see
[`CLAUDE.md`](CLAUDE.md) §"CRITICAL RULES" §6.

---

## Project Layout

```
security_buddy/
├── README.md                  ← you are here
├── CLAUDE.md                  ← operating manual (critical rules, conventions)
├── docs/
│   ├── ARCHITECTURE.md        ← multi-agent design, trust boundaries, tradeoffs
│   ├── THREAT_MODEL.md        ← OWASP LLM / MITRE ATLAS / HIPAA taxonomy
│   ├── USERS.md               ← three personas, automation justification
│   ├── TARGET_MANIFEST.md     ← target contract consumed by Red Team + Judge
│   ├── PLAN.md                ← slice-by-slice build plan
│   ├── EVAL_BASELINES.md      ← baselined accuracy for every LLM component
│   ├── COST_ANALYSIS.md       ← real spend + projections at 100/1K/10K/100K runs
│   └── findings/              ← exported vulnerability reports (VUL-0017, 0021, 0023)
├── apps/
│   ├── api/                   ← FastAPI + LangGraph + arq workers
│   │   └── tests/evals/       ← ground-truth eval sets + runners
│   └── ui/                    ← Next.js 15 operator console
├── docker-compose.yml         ← Postgres 16 + Redis 7
└── .github/workflows/         ← CI (ruff, mypy, import-linter, pytest)
```

---

## Build Status

Tracked in [`docs/PLAN.md`](docs/PLAN.md). Each slice is vertical
(schema → backend → UI → tests → docs) and merged one at a time.

- [x] **Slice 0** — Foundation: monorepo, schema, `llm_client`, health endpoint
- [x] **Slice 1** — Red Team Agent running live against the target
- [x] **Slice 2** — Judge Agent + ground-truth eval baseline (0.875 accuracy)
- [x] **Slice 3** — Orchestrator with priority function and budget enforcement
- [x] **Slice 4** — Documentation Agent with framework citations
- [x] **Slice 5** — Patch Agent + GitHub integration + branch protection
- [x] **Slice 6** — Regression Harness (replay, frozen rubrics, webhook → auto-sweep)
- [x] **Slice 7** — Security Buddy UI: dashboard, before/after diff, PR queue, `/cost`
- [~] **Slice 8** — Cost analysis + curated findings shipped; demo video pending

---

## License & Authorization Scope

This platform is built to attack **one configured target** that the operator
owns or is authorized to test (the Week-2 OpenEMR Clinical Co-Pilot).
Pointing it at any other system without authorization is outside the
platform's intended use. See [`docs/USERS.md`](docs/USERS.md) §6 for the full
"what this is not for" statement.
