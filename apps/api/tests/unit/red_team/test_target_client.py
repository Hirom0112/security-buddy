"""Unit tests for TargetClient.

All tests use respx to mock httpx — NO live calls are made.

Tests cover:
  1. Successful login flow: PHP login sets PHPSESSID, module page returns
     HTML with copilot-config script, JWT extracted.
  2. Login failure (form re-rendered): TargetAuthError raised.
  3. JWT extraction failure (missing script tag): TargetAuthError raised.
  4. fire_query with mocked agent-api response: returns TargetResponse.
  5. fire_query 401 expired → re-auth → retry → success.
  6. fire_query 5xx → TargetUnavailableError.
  7. Rate limit is acquired before request (verified by asserting the
     limiter's counter increments).
  8. Logs do NOT include the Bearer token (spot-check via log_event capture).
"""

import json
import uuid
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx
from pydantic import SecretStr

from src.agents.red_team.rate_limit import RateLimiter
from src.agents.red_team.target_client import (
    TargetAuthError,
    TargetClient,
    TargetUnavailableError,
)
from src.settings import Settings

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

OPENEMR_URL = "https://openemr.example.local"
AGENT_API_URL = "https://copilot-api.example.local"
MODULE_PATH = "/interface/modules/custom_modules/oe-module-clinical-copilot/index.php"

# A syntactically valid HS256 JWT (no real secret, not verified in tests).
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJwcm92aWRlci0xIiwic2lkIjoic2Vzc2lvbi1hYmMiLCJpc3MiOiJvcGVuZW1yLWNvcGlsb3QiLCJleHAiOjk5OTk5OTk5OTl9"
    ".FAKE_SIGNATURE"
)

COPILOT_CONFIG_HTML = f"""
<html>
<head><title>Co-Pilot</title></head>
<body>
<script id="copilot-config" type="application/json">
{{"jwt": "{FAKE_JWT}", "provider_id": "provider-1", "session_id": "session-abc"}}
</script>
</body>
</html>
"""

AGENT_QUERY_SUCCESS_BODY = json.dumps(
    {
        "narrative": "Patient Marcus Webb is stable.",
        "data": {},
        "citations": [],
        "errors": [],
    }
)


def make_settings() -> MagicMock:
    """Build a minimal Settings-like mock."""
    s = MagicMock(spec=Settings)
    s.target_base_url = AGENT_API_URL
    s.target_openemr_url = OPENEMR_URL
    s.target_copilot_module_path = MODULE_PATH
    s.target_login_user = "sara"
    s.target_login_password = SecretStr("chen")  # synthetic demo creds per TARGET_MANIFEST.md
    return s


def make_limiter() -> RateLimiter:
    """Fast RateLimiter with a huge burst so it never blocks tests."""
    return RateLimiter(requests_per_second=1000.0, burst=1000, campaign_attack_cap=100000)


# ---------------------------------------------------------------------------
# 1. Successful authentication flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_authenticate_success() -> None:
    """Two-step login succeeds: PHPSESSID set, JWT extracted."""
    login_url = f"{OPENEMR_URL}/interface/main/main_screen.php?auth=login&site=default"
    module_url = f"{OPENEMR_URL}{MODULE_PATH}"

    # Step 1: PHP login — respond with a non-login-form page.
    respx.post(login_url).mock(
        return_value=httpx.Response(
            302,
            headers={"Set-Cookie": "PHPSESSID=abc123; HttpOnly; Secure"},
            text="<html><body>Logged in</body></html>",
        )
    )
    # Step 2: Module page with copilot-config.
    respx.get(module_url).mock(return_value=httpx.Response(200, text=COPILOT_CONFIG_HTML))

    settings = make_settings()
    limiter = make_limiter()

    async with TargetClient(settings, limiter) as client:
        await client.authenticate()
        assert client._jwt == FAKE_JWT
        assert client._provider_id == "provider-1"
        assert client._session_id == "session-abc"


# ---------------------------------------------------------------------------
# 2. Login failure: form re-rendered
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_authenticate_credentials_rejected() -> None:
    """Login form re-rendered → TargetAuthError."""
    login_url = f"{OPENEMR_URL}/interface/main/main_screen.php?auth=login&site=default"
    # Return the login page again (contains authUser + clearPass fields).
    respx.post(login_url).mock(
        return_value=httpx.Response(
            200,
            text=("<form><input name='authUser'/><input name='clearPass' type='password'/></form>"),
        )
    )

    settings = make_settings()
    limiter = make_limiter()

    async with TargetClient(settings, limiter) as client:
        with pytest.raises(TargetAuthError, match="login form"):
            await client.authenticate()


# ---------------------------------------------------------------------------
# 3. JWT extraction failure: missing script tag
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_authenticate_missing_script_tag() -> None:
    """Module page without copilot-config → TargetAuthError."""
    login_url = f"{OPENEMR_URL}/interface/main/main_screen.php?auth=login&site=default"
    module_url = f"{OPENEMR_URL}{MODULE_PATH}"

    respx.post(login_url).mock(
        return_value=httpx.Response(
            302,
            headers={"Set-Cookie": "PHPSESSID=xyz999; HttpOnly; Secure"},
            text="<html><body>Logged in</body></html>",
        )
    )
    respx.get(module_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><body>No config here</body></html>",
        )
    )

    settings = make_settings()
    limiter = make_limiter()

    async with TargetClient(settings, limiter) as client:
        with pytest.raises(TargetAuthError, match="copilot-config script tag not found"):
            await client.authenticate()


# ---------------------------------------------------------------------------
# 4. fire_query success path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fire_query_success() -> None:
    """fire_query returns parsed TargetResponse with narrative."""
    _setup_auth_mocks()
    query_url = f"{AGENT_API_URL}/agent/query"
    respx.post(query_url).mock(return_value=httpx.Response(200, text=AGENT_QUERY_SUCCESS_BODY))

    settings = make_settings()
    limiter = make_limiter()
    campaign_id = uuid.uuid4()
    attack_id = uuid.uuid4()

    async with TargetClient(settings, limiter) as client:
        await client.authenticate()
        response = await client.fire_query(
            message="Summarize patient pt-001",
            attack_id=attack_id,
            campaign_id=campaign_id,
            patient_ids=["pt-001"],
        )

    assert response.status_code == 200
    assert response.narrative == "Patient Marcus Webb is stable."
    assert response.errors == []
    assert response.response_time_ms >= 0
    assert response.attempted_at is not None


# ---------------------------------------------------------------------------
# 5. fire_query 401 expired → re-auth → success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fire_query_reauth_on_expired() -> None:
    """On 401 with reason=expired, client re-authenticates and retries."""
    _setup_auth_mocks()

    query_url = f"{AGENT_API_URL}/agent/query"
    call_count = {"n": 0}

    def response_factory(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        if call_count["n"] == 1:
            return httpx.Response(
                401,
                json={"detail": {"error": "auth_failed", "reason": "expired"}},
            )
        return httpx.Response(200, text=AGENT_QUERY_SUCCESS_BODY)

    respx.post(query_url).mock(side_effect=response_factory)

    settings = make_settings()
    limiter = make_limiter()
    campaign_id = uuid.uuid4()
    attack_id = uuid.uuid4()

    async with TargetClient(settings, limiter) as client:
        await client.authenticate()
        # Force the JWT to be set so first call uses it.
        client._jwt = FAKE_JWT
        response = await client.fire_query(
            message="test message",
            attack_id=attack_id,
            campaign_id=campaign_id,
            patient_ids=["pt-001"],
        )

    assert response.status_code == 200
    # Two calls: initial 401, then retry after re-auth.
    assert call_count["n"] == 2


# ---------------------------------------------------------------------------
# 6. fire_query 5xx → TargetUnavailableError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fire_query_5xx_raises() -> None:
    """5xx response → TargetUnavailableError."""
    _setup_auth_mocks()
    query_url = f"{AGENT_API_URL}/agent/query"
    respx.post(query_url).mock(return_value=httpx.Response(503, text="Service Unavailable"))

    settings = make_settings()
    limiter = make_limiter()
    campaign_id = uuid.uuid4()
    attack_id = uuid.uuid4()

    async with TargetClient(settings, limiter) as client:
        await client.authenticate()
        with pytest.raises(TargetUnavailableError):
            await client.fire_query(
                message="test",
                attack_id=attack_id,
                campaign_id=campaign_id,
                patient_ids=["pt-001"],
            )


# ---------------------------------------------------------------------------
# 7. Rate limiter is acquired before request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_rate_limiter_is_called() -> None:
    """fire_query must call limiter.acquire before sending the HTTP request."""
    _setup_auth_mocks()
    query_url = f"{AGENT_API_URL}/agent/query"
    respx.post(query_url).mock(return_value=httpx.Response(200, text=AGENT_QUERY_SUCCESS_BODY))

    settings = make_settings()
    limiter = make_limiter()

    campaign_id = uuid.uuid4()
    attack_id = uuid.uuid4()

    async with TargetClient(settings, limiter) as client:
        await client.authenticate()
        await client.fire_query(
            message="test",
            attack_id=attack_id,
            campaign_id=campaign_id,
            patient_ids=["pt-001"],
        )

    # After one fire_query, the campaign counter should be 1.
    assert limiter.get_campaign_count(campaign_id=campaign_id) == 1


# ---------------------------------------------------------------------------
# 8. Logs do NOT include the Bearer token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_bearer_token_not_in_logs() -> None:
    """No log_event call should contain the raw Bearer token."""
    _setup_auth_mocks()
    query_url = f"{AGENT_API_URL}/agent/query"
    respx.post(query_url).mock(return_value=httpx.Response(200, text=AGENT_QUERY_SUCCESS_BODY))

    settings = make_settings()
    limiter = make_limiter()
    campaign_id = uuid.uuid4()
    attack_id = uuid.uuid4()

    logged_events: list[dict] = []

    def capture_log(name: str, **kwargs: object) -> None:
        logged_events.append({"event": name, **kwargs})

    with patch("src.agents.red_team.target_client.log_event", side_effect=capture_log):
        async with TargetClient(settings, limiter) as client:
            await client.authenticate()
            await client.fire_query(
                message="test message",
                attack_id=attack_id,
                campaign_id=campaign_id,
                patient_ids=["pt-001"],
            )

    # Check that none of the logged fields contain the fake JWT.
    for event in logged_events:
        for v in event.values():
            if isinstance(v, str):
                assert FAKE_JWT not in v, (
                    f"JWT found in log event {event['event']!r}: field value starts with {v[:60]!r}"
                )


# ---------------------------------------------------------------------------
# 9. TargetClient requires context manager
# ---------------------------------------------------------------------------


def test_requires_context_manager() -> None:
    """Calling _require_http outside a context manager raises RuntimeError."""
    settings = make_settings()
    limiter = make_limiter()
    client = TargetClient(settings, limiter)
    with pytest.raises(RuntimeError, match="context manager"):
        client._require_http()


# ---------------------------------------------------------------------------
# 10. Construction fails when required settings are missing
# ---------------------------------------------------------------------------


def test_missing_settings_raises() -> None:
    """Constructor raises ValueError when target settings are None."""
    s = MagicMock(spec=Settings)
    s.target_base_url = None  # Missing
    s.target_openemr_url = OPENEMR_URL
    s.target_copilot_module_path = MODULE_PATH
    s.target_login_user = "sara"
    s.target_login_password = SecretStr("chen")  # synthetic demo creds per TARGET_MANIFEST.md

    with pytest.raises(ValueError, match="TARGET_BASE_URL"):
        TargetClient(s, make_limiter())


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _setup_auth_mocks() -> None:
    """Register the two-step auth mocks for tests that need authentication."""
    login_url = f"{OPENEMR_URL}/interface/main/main_screen.php?auth=login&site=default"
    module_url = f"{OPENEMR_URL}{MODULE_PATH}"

    respx.post(login_url).mock(
        return_value=httpx.Response(
            302,
            headers={"Set-Cookie": "PHPSESSID=testcookie; HttpOnly; Secure"},
            text="<html><body>Welcome</body></html>",
        )
    )
    respx.get(module_url).mock(return_value=httpx.Response(200, text=COPILOT_CONFIG_HTML))
