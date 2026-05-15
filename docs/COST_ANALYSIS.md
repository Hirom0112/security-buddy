# Security Buddy — Cost Analysis

**Author:** Hirom Alarcon
**Week:** 3 — Gauntlet AI Austin Admission Track
**Status:** Living document. Numbers reflect campaign
`60662d6c-5614-46f5-bf86-e4087a50df4a` (2026-05-12), the first live run after
the OpenRouter $0 pricing bug was fixed in `apps/api/src/llm_client/pricing.py`.

---

## 1. Methodology

Cost is recorded per call. Every LLM invocation funnels through
`llm_client/` and writes a row into `agent_traces` carrying `agent`, `model`,
`tokens_in`, `tokens_out`, and `cost_usd`. The cost figure is **computed in
code** from the hardcoded rate table in `apps/api/src/llm_client/pricing.py`
because OpenRouter returns `usage.total_cost = 0` for
`anthropic/claude-sonnet-4.6` despite billing for the tokens. Per-agent and
per-campaign totals are pulled by direct aggregation:

```sql
SELECT agent, COUNT(*) AS calls,
       SUM(tokens_in) AS tokens_in,
       SUM(tokens_out) AS tokens_out,
       SUM(cost_usd) AS cost_usd
FROM agent_traces
WHERE campaign_id = :campaign
GROUP BY agent;
```

All numbers in §2 are measured. All numbers in §4 and §5 are projections from
those measurements with the assumption stated inline.

---

## 2. Real measured spend

Campaign 60662d6c ran 18 attacks against the deployed OpenEMR Clinical
Co-Pilot. The Judge evaluated 17 (one in flight at snapshot), produced 13
`exploit` / 2 `partial` / 2 `safe` verdicts, and the Documentation Agent
emitted 13 vulnerability reports.

| Agent          | Calls | Tokens in | Tokens out | Cost USD |
|----------------|------:|----------:|-----------:|---------:|
| orchestrator   |     1 |       577 |        754 |  $0.0130 |
| judge          |    17 |    40,229 |      4,512 |  $0.1884 |
| documentation  |    26 |    51,802 |     35,449 |  $0.6871 |
| **TOTAL**      |    44 |    92,608 |     40,715 |  **$0.8885** |

Unit economics:

- **$0.049 per attack** (18 attacks)
- **$0.068 per confirmed vulnerability** (13 reports)
- **77% of spend goes to the Documentation Agent.** It is the dominant cost
  center and the dominant latency contributor (~32s average per report). The
  Judge, by contrast, accounts for 21% of cost despite running on every attack
  — short structured rubric outputs keep its `tokens_out` low.

Every call in this campaign used `anthropic/claude-sonnet-4.6` at $3 / $15 per
MTok input/output.

---

## 3. Per-agent breakdown

### Orchestrator

Generates one campaign brief per run via Sonnet. The current implementation
also generates attack variants here, which is wrong per `ARCHITECTURE.md` §2 —
that work belongs to a dedicated Red Team Agent. Cost is shaped by the
coverage summary passed in as context; the slope is set by how much prior
campaign state we serialize into the brief. Caching prior-attack summaries
would flatten this.

### Judge

Runs once per attack. Cost is shaped by the size of the target's response
body (input tokens) and a deliberately tight rubric output schema (output
tokens). Pinned to `anthropic/claude-sonnet-4.6` at temperature 0 per
CLAUDE.md §6; the model cannot be swapped without a code commit and an eval
baseline diff. The slope here is set by attacks-per-campaign, not by
prompt-engineering choices.

### Documentation Agent

The cost-dominator. Produces long-form structured reports for every confirmed
or partial exploit — 26 calls for 13 reports implies an average of ~2 LLM
passes per report (likely draft + revise). Output tokens (~35K) outweigh input
tokens (~52K) less than for other agents because reports are long. What moves
this slope: model choice (Haiku for first-pass drafts), shorter target
templates, or skipping the revise pass when confidence is high.

### Red Team Agent

Not yet billed — the actual Red Team Agent (Llama 70B) is unimplemented; its
work currently runs through the Orchestrator on Sonnet. See §5.

### Patch Agent

First live run: 2026-05-14, VUL-0008 (multi-patient handoff PHI leak).

| Calls | Tokens in | Tokens out | Cost USD |
|------:|----------:|-----------:|---------:|
| 6     | 6,030     | 8,824      | $0.1505  |

6 calls = 3 code-search passes + 3 draft attempts (2 timed out at 60 s before
timeout was raised to 180 s; 1 succeeded). The successful draft generated
+480/−2,973 lines across 4 PHP files. Cost is dominated by tokens-out (the
full unified diff). Cost per successful patch: **$0.1505** at this draft size;
future runs will be cheaper as `PATCH_MAX_CANDIDATE_FILES=5` is the main lever
(fewer files → shorter diff → fewer output tokens).

---

## 4. Projection at scale

Baseline: **$0.8885 per campaign run**, measured.

| Scale       | Naive linear | Architecture-shift point                                                                                                        | One concrete optimization                                                  |
|-------------|-------------:|---------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| 100 runs    |      $88.85  | None. Current single-worker arq topology handles this trivially.                                                                | None needed.                                                               |
| 1K runs     |     $888.50  | Documentation Agent latency (~32s) becomes the queue bottleneck before cost does. Need parallel doc workers.                    | Run two arq doc workers; Postgres `SKIP LOCKED` already supports this.     |
| 10K runs    |   $8,885.00  | Documentation Agent is both cost (~77%) and latency bottleneck. The current "every exploit gets a Sonnet long-form report" design breaks. | Downgrade first-pass Documentation drafts to Haiku; reserve Sonnet for high-severity reports only. Estimated 40–50% Documentation cost cut. |
| 100K runs   |  $88,850.00  | Judge per-attack invocation becomes structurally expensive. Per-call overhead dominates and Sonnet rate limits start to bite.   | Batch the Judge: evaluate N attacks per call against the same rubric. Pricing is per-token, so batching trades a small input increase for amortized output overhead. |

The projections are linear in `$0.8885 × runs`. They do not include Postgres,
Redis, Railway, or LangSmith costs — those are flat or sub-linear at every
scale on this list and are not the dominant term.

---

## 5. What the Red Team rebuild will add

`docs/TODO.md` flags the Red Team Agent rebuild: variant generation and
adversarial mutation should move off Sonnet (running inside the Orchestrator
today) onto a hybrid stack with `meta-llama/llama-3.3-70b-instruct` for the
generation step. Rates in `apps/api/src/llm_client/pricing.py`:

- Sonnet: $3.00 / $15.00 per MTok
- Llama 3.3 70B Instruct: $0.23 / $0.40 per MTok — roughly **10–13× cheaper**

The current Orchestrator's $0.0130 per run is mostly variant-generation work
that will shift to Llama. At the same token shape, that drops to
~$0.00044/run — a saving of about **$0.0126/run**, or ~1.4% of total
campaign cost. The rebuild does **not** materially change the cost picture
because Documentation, not generation, is the dominant term. Its real value is
adversarial coverage (Llama lacks refusal training where Sonnet refuses
offensive workflows) and freeing Sonnet for the agents that need its
reasoning quality — the Judge and the Documentation Agent.

If the Red Team also adds *new* mutation passes that don't exist today
(multi-turn attack chains), those calls are net-new spend on Llama at
~$0.0004/call — a 10-call mutation chain still costs less than a single
Sonnet variant pass.

---

## 6. Levers, ranked by impact

1. **Downgrade Documentation first-pass drafts to Haiku.** Largest lever.
   Documentation is 77% of campaign cost; Haiku is ~12× cheaper than Sonnet
   on input and ~20× cheaper on output. Estimated 40–60% total-campaign cost
   reduction. Requires an eval baseline diff before merging.
2. **Batch the Judge across attacks.** 17 calls per campaign collapse to
   3–4 batched calls. Cuts Judge cost ~70% and reduces per-call overhead.
3. **Cache prior-attack summaries for Orchestrator briefs.** Today the
   Orchestrator re-reads coverage state on every run. Caching a rolling
   summary in Postgres trims the input-token slope as campaign count grows.
4. **Drop temperature-0 fallback retries on the Judge.** When the Judge
   returns malformed JSON, the harness retries. Tightening the rubric schema
   and adding a JSON-mode constraint removes most retries — small lever per
   run, but it compounds at 10K+ runs.
