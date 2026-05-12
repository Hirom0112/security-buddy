"""seed_attack_taxonomy

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-11 00:00:02.000000

Seeds the attack_taxonomy table from THREAT_MODEL.md §4.

Row count discrepancy note:
  THREAT_MODEL.md §1 (Summary) states "thirteen subcategories". However,
  §4 enumerates the subcategories explicitly across six attack categories:
    §4.1 Prompt Injection:              3 subcategories
    §4.2 Sensitive Information:         3 subcategories
    §4.3 State Corruption:              2 subcategories
    §4.4 Excessive Agency (Tool Misuse):3 subcategories
    §4.5 Unbounded Consumption (DoS):   2 subcategories
    §4.6 Identity and Role Exploitation:3 subcategories
    TOTAL: 16 subcategories

  We seed 16 rows — accuracy to the authoritative enumeration in §4 takes
  precedence over the summary paragraph count. The "thirteen" in §1 appears
  to be a writing error (likely written before §4.5 and §4.6 were expanded).
  The THREAT_MODEL.md §1 summary paragraph will be corrected in a docs PR.

Each row's description is the first sentence of the "Surface:" paragraph
for that subcategory, verbatim from THREAT_MODEL.md §4.

framework_versions is pinned to:
  {"owasp_llm": "2025-v2.0", "mitre_atlas": "5.1.0", "hipaa": "2013-omnibus"}
per CLAUDE.md §6a and THREAT_MODEL.md §6.
"""

import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Pinned framework versions — must match CLAUDE.md §6a
FRAMEWORK_VERSIONS = {
    "owasp_llm": "2025-v2.0",
    "mitre_atlas": "5.1.0",
    "hipaa": "2013-omnibus",
}

# fmt: off
TAXONOMY_ROWS = [
    # -------------------------------------------------------------------------
    # §4.1 Prompt Injection (3 subcategories)
    # -------------------------------------------------------------------------
    {
        "category": "prompt_injection",
        "subcategory": "prompt_injection/direct",
        "priority": "high",
        "description": (
            "The user's chat input is concatenated or templated into the "
            "LLM's prompt."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051.000",
            "hipaa": ["164.312(a)(1)"],
        },
    },
    {
        "category": "prompt_injection",
        "subcategory": "prompt_injection/indirect_via_upload",
        "priority": "critical",
        "description": (
            "A PDF, image, or other document is uploaded and its extracted "
            "content is passed to the LLM as part of context."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051.001",
            "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
        },
    },
    {
        "category": "prompt_injection",
        "subcategory": "prompt_injection/multi_turn_drift",
        "priority": "high",
        "description": (
            "The conversation history is passed back to the LLM on every "
            "turn."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051",
            "hipaa": ["164.312(a)(1)"],
        },
    },
    # -------------------------------------------------------------------------
    # §4.2 Sensitive Information Disclosure (3 subcategories)
    # -------------------------------------------------------------------------
    {
        "category": "data_exfiltration",
        "subcategory": "data_exfiltration/cross_patient_leakage",
        "priority": "critical",
        "description": (
            "A physician's session has access to their assigned patient "
            "panel."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM02:2025",
            "mitre_atlas": "AML.T0057",
            "hipaa": ["164.312(a)(1)", "164.308(a)(4)"],
        },
    },
    {
        "category": "data_exfiltration",
        "subcategory": "data_exfiltration/phi_in_errors",
        "priority": "medium",
        "description": (
            "When the Co-Pilot encounters an error or edge case, it may "
            "echo back internal context — patient identifiers, query "
            "parameters, tool inputs — in the error response."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM02:2025",
            "mitre_atlas": "AML.T0057",
            "hipaa": ["164.312(b)", "164.312(a)(1)"],
        },
    },
    {
        "category": "data_exfiltration",
        "subcategory": "data_exfiltration/authz_via_tool_args",
        "priority": "high",
        "description": (
            "When the LLM synthesizes tool calls, the arguments come from "
            "the conversation context (which is attacker-influenceable)."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM02:2025",
            "mitre_atlas": "AML.T0086",
            "hipaa": ["164.312(a)(1)", "164.308(a)(4)"],
        },
    },
    # -------------------------------------------------------------------------
    # §4.3 State Corruption (2 subcategories)
    # -------------------------------------------------------------------------
    {
        "category": "state_corruption",
        "subcategory": "state_corruption/conversation_history",
        "priority": "high",
        "description": (
            "If the conversation history can be edited, prepended, or "
            "truncated by the client, an attacker can inject fake "
            "\"earlier turns\" that the Co-Pilot reads as authoritative."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051",
            "hipaa": ["164.312(c)(1)", "164.312(b)"],
        },
    },
    {
        "category": "state_corruption",
        "subcategory": "state_corruption/context_eviction",
        "priority": "high",
        "description": (
            "Push the system prompt or earlier safety-relevant turns out "
            "of the context window by flooding with low-value content, "
            "then attack without the safeguards in scope."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051",
            "hipaa": ["164.312(a)(1)"],
        },
    },
    # -------------------------------------------------------------------------
    # §4.4 Excessive Agency / Tool Misuse (3 subcategories)
    # -------------------------------------------------------------------------
    {
        "category": "tool_misuse",
        "subcategory": "tool_misuse/unintended_invocation",
        "priority": "critical",
        "description": (
            "The Co-Pilot's tool layer exposes operations (chart write, "
            "prescription, schedule, message patient) that are appropriate "
            "in some clinical contexts and not others."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM06:2025",
            "mitre_atlas": "AML.T0086",
            "hipaa": ["164.312(c)(1)", "164.312(a)(2)(iv)"],
        },
    },
    {
        "category": "tool_misuse",
        "subcategory": "tool_misuse/parameter_tampering",
        "priority": "high",
        "description": (
            "Even when the right tool is invoked, the parameters may be "
            "attacker-controllable in subtle ways."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM06:2025",
            "mitre_atlas": "AML.T0086",
            "hipaa": ["164.312(c)(1)"],
        },
    },
    {
        "category": "tool_misuse",
        "subcategory": "tool_misuse/recursive_calls",
        "priority": "medium",
        "description": (
            "A tool's output becomes input to another tool call."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM06:2025",
            "mitre_atlas": "AML.T0029",
            "hipaa": ["164.308(a)(7)"],
        },
    },
    # -------------------------------------------------------------------------
    # §4.5 Unbounded Consumption / DoS (2 subcategories)
    # -------------------------------------------------------------------------
    {
        "category": "dos",
        "subcategory": "dos/token_exhaustion",
        "priority": "medium",
        "description": (
            "Crafted inputs that force the model to generate "
            "maximum-length responses, or queries that pull maximum-size "
            "retrieval results."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM10:2025",
            "mitre_atlas": "AML.T0029",
            "hipaa": ["164.308(a)(7)", "164.312(e)(1)"],
        },
    },
    {
        "category": "dos",
        "subcategory": "dos/recursive_amplification",
        "priority": "high",
        "description": (
            "Same as tool_misuse/recursive_calls with DoS framing."
            " Loops that consume LLM calls until manually halted."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM10:2025",
            "mitre_atlas": "AML.T0029",
            "hipaa": ["164.308(a)(7)"],
        },
    },
    # -------------------------------------------------------------------------
    # §4.6 Identity and Role Exploitation (3 subcategories)
    # -------------------------------------------------------------------------
    {
        "category": "identity_role",
        "subcategory": "identity_role/privilege_escalation",
        "priority": "critical",
        "description": (
            "The Co-Pilot has a persona (\"you are a physician's "
            "assistant\") encoded in its system prompt."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM06:2025",
            "mitre_atlas": "AML.T0054",
            "hipaa": ["164.308(a)(4)", "164.312(a)(1)"],
        },
    },
    {
        "category": "identity_role",
        "subcategory": "identity_role/persona_hijacking",
        "priority": "high",
        "description": (
            "Convince the Co-Pilot to abandon its scoped persona "
            "entirely and act as a general-purpose assistant or a "
            "different persona."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0054",
            "hipaa": ["164.312(a)(1)"],
        },
    },
    {
        "category": "identity_role",
        "subcategory": "identity_role/trust_boundary_violation",
        "priority": "high",
        "description": (
            "A document, chat message, or retrieved record contains "
            "content that the model treats as instructions from a "
            "trusted source (\"the attending physician has asked you "
            "to...\" embedded in a clinical note)."
        ),
        "framework_mappings": {
            "owasp_llm": "LLM01:2025",
            "mitre_atlas": "AML.T0051.001",
            "hipaa": ["164.312(a)(1)", "164.312(c)(1)"],
        },
    },
]
# fmt: on


def upgrade() -> None:
    import json

    from sqlalchemy.dialects.postgresql import JSONB as _JSONB
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    # Build the INSERT using the connection directly — no ORM, no model import.
    # We use pg_insert().on_conflict_do_nothing() for idempotency.
    #
    # asyncpg / SQLAlchemy asyncpg dialect quirk: when using sa.table() with
    # untyped columns, Python dicts are not automatically serialised to JSONB.
    # The fix is to wrap JSON strings in sa.cast(..., JSONB()) so SQLAlchemy
    # emits an explicit CAST expression that asyncpg handles without needing
    # the parameter itself to be pre-serialised to bytes. Using sa.cast() on a
    # string literal (not a bound parameter) avoids the ::cast shorthand that
    # asyncpg rejects in parameterised-query position.
    #
    # Concretely: sa.cast(sa.literal(json_str), JSONB()) compiles to
    # CAST('<json>' AS JSONB) which is valid in both the VALUES clause and
    # asyncpg's prepared-statement model.
    conn = op.get_bind()

    attack_taxonomy = sa.table(
        "attack_taxonomy",
        sa.column("id"),
        sa.column("category", sa.Text()),
        sa.column("subcategory", sa.Text()),
        sa.column("priority", sa.Text()),
        sa.column("description", sa.Text()),
        sa.column("framework_mappings", _JSONB()),
        sa.column("framework_versions", _JSONB()),
        sa.column("created_at"),
    )

    for row in TAXONOMY_ROWS:
        stmt = (
            pg_insert(attack_taxonomy)
            .values(
                id=sa.func.gen_random_uuid(),
                category=row["category"],
                subcategory=row["subcategory"],
                priority=row["priority"],
                description=row["description"],
                framework_mappings=sa.cast(
                    sa.literal(json.dumps(row["framework_mappings"])), _JSONB()
                ),
                framework_versions=sa.cast(
                    sa.literal(json.dumps(FRAMEWORK_VERSIONS)), _JSONB()
                ),
                created_at=sa.func.now(),
            )
            .on_conflict_do_nothing(index_elements=["subcategory"])
        )
        conn.execute(stmt)


def downgrade() -> None:
    conn = op.get_bind()
    subcategories = [r["subcategory"] for r in TAXONOMY_ROWS]
    # Use sa.text with a list literal; ANY() accepts a Python list via asyncpg.
    for sub in subcategories:
        conn.execute(
            sa.text("DELETE FROM attack_taxonomy WHERE subcategory = :sub"),
            {"sub": sub},
        )
