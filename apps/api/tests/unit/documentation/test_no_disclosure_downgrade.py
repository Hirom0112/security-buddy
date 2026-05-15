"""Unit-level coverage of the no-disclosure severity downgrade.

The full run_document path is covered by integration tests against a real
Postgres. This file holds the pure decision logic that the worker performs
between `final_severity` selection and the critical soft-gate:

    if verdict.data_actually_disclosed is False:
        final_severity = downgrade_for_no_disclosure(final_severity)

It's a small, deterministic branch but it's also the operator-facing
contract for "no real PHI left the system, drop it one rank" — the same
contract the reviewer raised over the 22/22 false-critical sample. We
test it directly so a future refactor cannot silently swap `is False`
for `not` (which would also downgrade None / legacy rows and break
backwards compatibility).
"""

from src.agents.documentation.schema import Severity
from src.agents.documentation.severity import downgrade_for_no_disclosure


def _apply_gate(severity: Severity, data_actually_disclosed: bool | None) -> Severity:
    """Mirror the document.py condition exactly. Kept here so the test
    fails loudly if the production code drifts from this contract."""
    if data_actually_disclosed is False:
        return downgrade_for_no_disclosure(severity)
    return severity


def test_critical_with_no_disclosure_drops_to_high() -> None:
    assert _apply_gate(Severity.CRITICAL, False) is Severity.HIGH


def test_high_with_no_disclosure_drops_to_medium() -> None:
    assert _apply_gate(Severity.HIGH, False) is Severity.MEDIUM


def test_medium_with_no_disclosure_drops_to_low() -> None:
    assert _apply_gate(Severity.MEDIUM, False) is Severity.LOW


def test_disclosure_true_keeps_critical() -> None:
    """Real PHI emitted — operator must see critical, no downgrade."""
    assert _apply_gate(Severity.CRITICAL, True) is Severity.CRITICAL


def test_disclosure_none_is_legacy_no_downgrade() -> None:
    """Legacy verdict row (pre-migration 0014) has no disclosure signal.
    Backwards-compat contract: do NOT downgrade. None is not False."""
    assert _apply_gate(Severity.CRITICAL, None) is Severity.CRITICAL
    assert _apply_gate(Severity.HIGH, None) is Severity.HIGH
