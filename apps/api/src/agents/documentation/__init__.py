"""Documentation agent — exploit verdicts → structured vulnerability reports.

Reads a verdicts row with verdict='exploit', composes a Markdown report
grounded in the attack + manifest + frozen rubric, looks up the framework
citations from attack_taxonomy, and persists a vulnerabilities row.

Severity flow:
  - Deterministic severity classifier from severity.py runs first
    (subcategory + violated boundaries).
  - LLM proposes severity in its draft.
  - Worker takes the more-severe of the two as a defensive choice.

Critical soft gate (CLAUDE.md §"Critical-severity soft gate"):
  status='draft' for severity=critical, 'open' for high/medium/low.
"""
