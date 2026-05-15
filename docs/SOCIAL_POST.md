# Security Buddy — Social Posts

Final-submission deliverable. Two versions, both engineer-to-engineer voice.

---

## X / Twitter (280 char)

Built a 5-agent red team that attacks a live AI clinical co-pilot 24/7.

Best moment: it caught its own bad patch. Patch Agent fixed VUL-0017, opened the PR, merged it — then the regression harness replayed the exploit 3/3 times. Fix didn't hold. The loop called itself out.

---

## LinkedIn (~220 words)

The most interesting thing I built this month is a system that proved its own patch didn't work.

Security Buddy is a continuous adversarial evaluation platform for AI-assisted clinical workflows. Five agents, each with one job, coordinating through Postgres as a durable message bus:

- Orchestrator (Claude Sonnet) — priority function, budget enforcement
- Red Team (open-weights Llama 70B) — generates and fires novel attacks live
- Judge (Claude Sonnet, pinned model, temperature 0) — independent verdict
- Documentation Agent — writes reports with OWASP LLM Top 10, MITRE ATLAS, and HIPAA citations on every finding
- Patch Agent — opens PRs against the target's fork. Cannot merge. Human gate enforced by branch protection.

Pointed it at a live deployed OpenEMR Clinical Co-Pilot. First campaign: 18 attacks, 13 confirmed exploits, 13 reports drafted. Judge baselined at 0.875 accuracy against a ground-truth set.

Then the demo signal I wasn't expecting: VUL-0017 (out-of-panel patient access) got confirmed, the Patch Agent generated a fix in 131 seconds, the PR merged, and the regression sweep replayed the exploit — 3/3 still worked. The loop flagged its own patch as `regressed`.

The point isn't catching one jailbreak. The point is whether the system gets more resilient over time. That requires a measurement instrument that doesn't lie to you about its own work.

Repo + writeup in comments.
