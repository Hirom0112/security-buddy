"""Domain entity for a HappyPathFixture.

A happy-path fixture is a canonical "legitimate clinician query + expected
response shape" pair anchored to a target_manifest capability. The
regression harness fires every enabled fixture after a patch merge and
flips the patch+vuln to over_fit / blocks_legit_features if any required
substring goes missing from the target's response.

Returned by HappyPathFixtureRepository. ORM details stay in the repository.
The substring-match heuristic is intentionally lo-fi — we're catching
over-fit patches, not building a conformance framework (CLAUDE.md / TODO
"Product insight 2026-05-14").
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class HappyPathFixture(BaseModel):
    """Parsed happy_path_fixtures row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    target_manifest_id: UUID
    capability_name: str
    attack_input: str
    expected_response_shape: dict[str, Any]
    enabled: bool
    created_at: datetime
    version_id: int

    def required_substrings(self) -> list[str]:
        """Pull the substring list out of the shape dict.

        Returns an empty list if the shape is malformed. Defensive because
        the column is JSONB and could in principle hold anything; the
        harness must not crash on a bad fixture, just fail-open.
        """
        raw = self.expected_response_shape.get("required_substrings", [])
        if not isinstance(raw, list):
            return []
        return [str(s) for s in raw]
