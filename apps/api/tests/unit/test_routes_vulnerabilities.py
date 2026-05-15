"""Unit tests for POST /api/v1/vulnerabilities/{id}/decide.

Covers the dismiss-with-reason audit trail (CLAUDE.md §"Critical-severity
soft gate"). Dismiss must require a non-empty reason and persist an entry
to vulnerabilities.notes via append_note(); confirm continues to flip
draft → open and enqueue the Patch Agent.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

# Match the env-var bootstrap from test_routes_campaigns.py — these settings
# must be present before src.* imports run.
os.environ.setdefault(
    "DATABASE_URL",
    "postgresql+asyncpg://security_buddy:security_buddy@localhost:5432/security_buddy",
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("OPENROUTER_API_KEY", "stub")
os.environ.setdefault("LANGSMITH_API_KEY", "DISABLED")
os.environ.setdefault("LANGSMITH_PROJECT", "test")
os.environ.setdefault("SESSION_SECRET", "a" * 32)
os.environ.setdefault("TARGET_BASE_URL", "https://target.example.com")
os.environ.setdefault("TARGET_OPENEMR_URL", "https://openemr.example.com")
os.environ.setdefault(
    "TARGET_COPILOT_MODULE_PATH", "/interface/modules/custom_modules/copilot/index.php"
)
os.environ.setdefault("TARGET_LOGIN_USER", "sara")
os.environ.setdefault("TARGET_LOGIN_PASSWORD", "chen")

from src.domain.vulnerability import (
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from src.main import app

_VULN_ID = uuid4()


def _fake_vuln(
    status: VulnerabilityStatus = VulnerabilityStatus.DRAFT,
    notes: list[dict[str, Any]] | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=_VULN_ID,
        vuln_id="VUL-0001",
        attack_id=uuid4(),
        verdict_id=uuid4(),
        severity=VulnerabilitySeverity.CRITICAL,
        title="Synthetic finding for tests",
        clinical_impact="x",
        reproduction_steps="x",
        observed_behavior="x",
        expected_behavior="x",
        recommended_remediation="x",
        status=status,
        owasp_llm_id="LLM01:2025",
        mitre_atlas_technique_id="AML.T0051",
        hipaa_safeguard="164.312(b)",
        framework_versions={"owasp_llm": "2025-v2.0"},
        target_version_id=None,
        rubric_snapshot=None,
        created_at=datetime.now(UTC),
        version_id=1,
        notes=notes or [],
    )


@pytest.fixture
def client() -> TestClient:
    mock_factory = MagicMock()
    fake_session = AsyncMock()
    mock_factory.return_value.__aenter__ = AsyncMock(return_value=fake_session)
    mock_factory.return_value.__aexit__ = AsyncMock(return_value=None)

    app.state.session_factory = mock_factory
    if not hasattr(app.state, "limiter"):
        from slowapi import Limiter
        from slowapi.util import get_remote_address

        app.state.limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

    return TestClient(app, raise_server_exceptions=False)


@patch("src.routes.vulnerabilities.VulnerabilityRepository")
def test_dismiss_requires_reason(
    mock_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    """Dismiss without a reason returns 422 and never touches the row."""
    repo = mock_repo_cls.return_value
    repo.get_by_id = AsyncMock(return_value=_fake_vuln())
    repo.append_note = AsyncMock()

    resp = client.post(
        f"/api/v1/vulnerabilities/{_VULN_ID}/decide",
        json={"decision": "dismiss"},
    )

    assert resp.status_code == 422, resp.text
    repo.append_note.assert_not_called()


@patch("src.routes.vulnerabilities.VulnerabilityRepository")
def test_dismiss_reason_too_short(
    mock_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    """Reason shorter than 4 chars (post-strip) fails validation."""
    repo = mock_repo_cls.return_value
    repo.get_by_id = AsyncMock(return_value=_fake_vuln())
    repo.append_note = AsyncMock()

    resp = client.post(
        f"/api/v1/vulnerabilities/{_VULN_ID}/decide",
        json={"decision": "dismiss", "reason": "  x  "},
    )

    assert resp.status_code == 422, resp.text
    repo.append_note.assert_not_called()


@patch("src.routes.vulnerabilities.VulnerabilityRepository")
def test_dismiss_appends_note(
    mock_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    """Valid dismiss persists an audit note and returns the updated row."""
    repo = mock_repo_cls.return_value
    repo.get_by_id = AsyncMock(return_value=_fake_vuln())
    updated_note: dict[str, Any] = {
        "at": "2026-05-15T00:00:00+00:00",
        "actor": "operator",
        "action": "dismiss",
        "reason": "false positive — synthetic alias not a real leak",
    }
    repo.append_note = AsyncMock(
        return_value=_fake_vuln(notes=[updated_note]),
    )

    resp = client.post(
        f"/api/v1/vulnerabilities/{_VULN_ID}/decide",
        json={
            "decision": "dismiss",
            "reason": "false positive — synthetic alias not a real leak",
        },
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "draft"  # dismiss does not change status
    assert len(body["notes"]) == 1
    assert body["notes"][0]["action"] == "dismiss"
    assert body["notes"][0]["reason"].startswith("false positive")

    repo.append_note.assert_called_once()
    call_kwargs = repo.append_note.call_args.kwargs
    note = call_kwargs["note"]
    assert note["action"] == "dismiss"
    assert note["actor"] == "operator"
    assert note["reason"] == "false positive — synthetic alias not a real leak"
    assert "at" in note
    assert call_kwargs["expected_version_id"] == 1


@patch("src.routes.vulnerabilities.VulnerabilityRepository")
def test_dismiss_optimistic_lock_conflict(
    mock_repo_cls: MagicMock,
    client: TestClient,
) -> None:
    """append_note returning None → 409 Conflict."""
    repo = mock_repo_cls.return_value
    repo.get_by_id = AsyncMock(return_value=_fake_vuln())
    repo.append_note = AsyncMock(return_value=None)

    resp = client.post(
        f"/api/v1/vulnerabilities/{_VULN_ID}/decide",
        json={"decision": "dismiss", "reason": "stale view"},
    )

    assert resp.status_code == 409, resp.text


@patch("src.routes.vulnerabilities.enqueue_patch_propose", new_callable=AsyncMock)
@patch("src.routes.vulnerabilities.VulnerabilityRepository")
def test_confirm_still_works(
    mock_repo_cls: MagicMock,
    mock_enqueue: AsyncMock,
    client: TestClient,
) -> None:
    """Confirm continues to flip draft → open and enqueue the Patch Agent."""
    repo = mock_repo_cls.return_value
    repo.get_by_id = AsyncMock(return_value=_fake_vuln())
    repo.update_status = AsyncMock(return_value=_fake_vuln(status=VulnerabilityStatus.OPEN))

    resp = client.post(
        f"/api/v1/vulnerabilities/{_VULN_ID}/decide",
        json={"decision": "confirm"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "open"
    mock_enqueue.assert_called_once()
