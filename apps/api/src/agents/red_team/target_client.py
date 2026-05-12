"""Authenticated HTTP client for the OpenEMR Clinical Co-Pilot agent-api.

Authentication is a two-step process (TARGET_MANIFEST.md §2):

  Step 1 — OpenEMR PHP login (Door A)
    POST {TARGET_OPENEMR_URL}/interface/main/main_screen.php
         ?auth=login&site=default
    body: application/x-www-form-urlencoded
    On success: PHPSESSID cookie set. On failure: HTTP 200 with login form
    re-rendered (detect by checking body for the login-form signature).

  Step 2 — JWT extraction (Door B)
    GET {TARGET_OPENEMR_URL}{TARGET_COPILOT_MODULE_PATH} with PHPSESSID cookie.
    Response: HTML containing a <script id="copilot-config" type="application/json">
    {"jwt":"...","provider_id":"...","session_id":"..."}</script> blob.
    Parse the blob; extract jwt, provider_id, session_id.

Subsequent calls: POST {TARGET_BASE_URL}/agent/query
    Authorization: Bearer <jwt>
    Rate-limited via RateLimiter before each request.

SECURITY rules (CLAUDE.md §2, §4):
  - No secrets in logs. The JWT is never logged — only its sub/exp claims.
  - The client only connects to the configured target URLs. No other hosts.
  - Attack payloads flow as data into HTTP request bodies. They are never
    eval'd, templated into prompts, or treated as instructions.
  - No subprocess, no shell calls, no eval.
"""

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from types import TracebackType
from typing import Any
from uuid import UUID

import httpx

from src.agents.red_team.rate_limit import RateLimiter
from src.observability.events import log_event
from src.settings import Settings

# Maximum size of response body we store (100 kB per spec).
_MAX_RESPONSE_BODY_BYTES: int = 100 * 1024

# Pattern to locate the copilot-config JSON blob in the module page HTML.
_COPILOT_CONFIG_RE: re.Pattern[str] = re.compile(
    r'<script[^>]+id=["\']copilot-config["\'][^>]*>(.*?)</script>',
    re.DOTALL,
)

# Signature that indicates the login form was re-rendered (PHP login failure).
# The login page always contains this input name.
_LOGIN_FORM_SIGNATURE = "authUser"


class TargetAuthError(Exception):
    """Bootstrap login failed, JWT could not be parsed, or re-auth failed."""


class TargetUnavailableError(Exception):
    """Target returned 5xx, connection refused, or DNS failure."""


class TargetRateLimitedError(Exception):
    """Target returned 429 (we self-throttle but handle this defensively)."""


class TargetUnexpectedShapeError(Exception):
    """Response body was not the expected {narrative, data, citations, errors} shape."""


class TargetResponse:
    """Parsed response from a single POST /agent/query call.

    This is a plain class (not Pydantic) because it is constructed by
    TargetClient and consumed immediately — it never crosses a serialization
    boundary. If it needs to be serialized, convert to a dict first.
    """

    def __init__(
        self,
        *,
        status_code: int,
        response_time_ms: int,
        response_body: str,
        response_headers: dict[str, str],
        narrative: str | None,
        errors: list[str],
        attempted_at: datetime,
    ) -> None:
        self.status_code = status_code
        self.response_time_ms = response_time_ms
        self.response_body = response_body
        self.response_headers = response_headers
        self.narrative = narrative
        self.errors = errors
        self.attempted_at = attempted_at


class TargetClient:
    """Authenticated HTTP client for the OpenEMR Clinical Co-Pilot agent-api.

    Single-target by design. Never connects to anything other than the
    URLs in settings (TARGET_OPENEMR_URL, TARGET_BASE_URL).

    Usage::

        async with TargetClient(settings, rate_limiter) as client:
            await client.authenticate()
            response = await client.fire_query(
                message="...",
                attack_id=attack_id,
                campaign_id=campaign_id,
                patient_ids=["pt-001"],
            )
    """

    def __init__(self, settings: Settings, rate_limiter: RateLimiter) -> None:
        """Construct the client. Does not open any connections.

        Args:
            settings: Application settings. Must have target_base_url,
                target_login_user, target_login_password set (not None).
                Raises ValueError if any required target field is missing.
            rate_limiter: Shared outbound rate limiter.
        """
        if settings.target_base_url is None:
            raise ValueError("TARGET_BASE_URL is required but not set")
        if not hasattr(settings, "target_openemr_url") or settings.target_openemr_url is None:
            raise ValueError("TARGET_OPENEMR_URL is required but not set")
        if (
            not hasattr(settings, "target_copilot_module_path")
            or settings.target_copilot_module_path is None
        ):
            raise ValueError("TARGET_COPILOT_MODULE_PATH is required but not set")
        if settings.target_login_user is None:
            raise ValueError("TARGET_LOGIN_USER is required but not set")
        if settings.target_login_password is None:
            raise ValueError("TARGET_LOGIN_PASSWORD is required but not set")

        self._agent_api_url: str = settings.target_base_url.rstrip("/")
        self._openemr_url: str = settings.target_openemr_url.rstrip("/")
        self._module_path: str = settings.target_copilot_module_path
        self._login_user: str = settings.target_login_user
        self._login_password: str = settings.target_login_password.get_secret_value()
        self._rate_limiter: RateLimiter = rate_limiter

        # Auth state — set by authenticate().
        self._jwt: str | None = None
        self._provider_id: str | None = None
        self._session_id: str | None = None
        self._jwt_exp: float | None = None  # Unix timestamp
        self._provider_name: str = "Provider"  # overwritten in _step2
        self._panel_patient_ids: list[str] = []  # overwritten in _step2

        # The httpx client is created in __aenter__.
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "TargetClient":
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0),
            follow_redirects=True,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def authenticate(self) -> None:
        """Run the two-step OpenEMR login → JWT extraction.

        Idempotent: if a valid (non-expired) JWT is already cached with at
        least 60 seconds remaining, this method returns immediately.

        Raises:
            TargetAuthError: If login fails, the login form is re-rendered,
                the copilot-config script tag is missing, or the JWT field
                is absent from the JSON blob.
            TargetUnavailableError: If the target is unreachable.
        """
        # Skip if we have a valid cached JWT with > 60 s remaining.
        if self._jwt is not None and self._jwt_exp is not None:
            remaining = self._jwt_exp - time.time()
            if remaining > 60:
                return

        openemr_host = self._openemr_url
        log_event(
            "target_login_attempt",
            host=openemr_host,
            user=self._login_user,
            outcome="started",
        )

        # Step 1: PHP login (returns the full session cookie jar — OpenEMR
        # actually issues a cookie named `OpenEMR`, not `PHPSESSID` as the
        # manifest stated; pass forward whatever the server sets).
        session_cookies = await self._step1_php_login()

        # Step 2: Extract JWT from the module page.
        await self._step2_extract_jwt(session_cookies)

        log_event(
            "target_jwt_extracted",
            provider_id=self._provider_id,
            session_id=self._session_id,
            jwt_exp=self._jwt_exp,
            # NEVER log the JWT itself — only metadata.
        )

    async def _step1_php_login(self) -> dict[str, str]:
        """POST OpenEMR login form. Returns the session cookie jar.

        OpenEMR's response sets a session cookie (observed name: `OpenEMR`,
        though older versions used `PHPSESSID`). We propagate every cookie
        from the response rather than picking by name — this is robust to
        version drift and matches what a real browser would do.
        """
        http = self._require_http()
        login_url = f"{self._openemr_url}/interface/main/main_screen.php?auth=login&site=default"
        body = {
            "authUser": self._login_user,
            "clearPass": self._login_password,
            "new_login_session_management": "1",
            "languageChoice": "1",
        }

        try:
            # Do NOT follow redirects: OpenEMR responds 302 with the session
            # cookie in Set-Cookie. Following the redirect lands on a page
            # whose response has no cookies, and httpx's `resp.cookies`
            # surfaces only the final response's cookies — so we'd see
            # nothing. Capture cookies from the immediate 302 instead.
            resp = await http.post(
                login_url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=False,
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            log_event(
                "target_login_attempt",
                host=self._openemr_url,
                outcome="network_failure",
                error_class=type(exc).__name__,
            )
            raise TargetUnavailableError(
                f"OpenEMR login endpoint unreachable: {type(exc).__name__}"
            ) from exc

        if resp.status_code >= 500:
            log_event(
                "target_login_attempt",
                host=self._openemr_url,
                outcome="server_error",
                status_code=resp.status_code,
            )
            raise TargetUnavailableError(f"OpenEMR returned {resp.status_code} on login")

        # OpenEMR signals success with a 302 redirect to /interface/main/...,
        # and signals failure with a 200 that re-renders the login form.
        is_login_form = (
            resp.status_code == 200
            and _LOGIN_FORM_SIGNATURE in resp.text
            and "clearPass" in resp.text
        )
        if is_login_form:
            log_event(
                "target_login_attempt",
                host=self._openemr_url,
                outcome="credentials_rejected",
                status_code=resp.status_code,
            )
            raise TargetAuthError(
                "OpenEMR login failed: response contained the login form "
                "(credentials rejected or CSRF mismatch)"
            )

        # Capture every cookie the server set on this response.
        session_cookies = {name: value for name, value in resp.cookies.items()}

        if not session_cookies:
            log_event(
                "target_login_attempt",
                host=self._openemr_url,
                outcome="missing_cookie",
                status_code=resp.status_code,
            )
            raise TargetAuthError(
                "OpenEMR login appeared to succeed but no session cookie was issued"
            )

        log_event(
            "target_login_attempt",
            host=self._openemr_url,
            outcome="success",
            status_code=resp.status_code,
            cookie_names=sorted(session_cookies.keys()),
        )
        return session_cookies

    async def _step2_extract_jwt(self, session_cookies: dict[str, str]) -> None:
        """GET the module page with the login session cookies, parse the
        copilot-config JSON blob.
        """
        http = self._require_http()
        module_url = f"{self._openemr_url}{self._module_path}"

        try:
            resp = await http.get(
                module_url,
                cookies=session_cookies,
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            raise TargetUnavailableError(f"Module page unreachable: {type(exc).__name__}") from exc

        if resp.status_code >= 500:
            raise TargetUnavailableError(f"Module page returned {resp.status_code}")

        match = _COPILOT_CONFIG_RE.search(resp.text)
        if match is None:
            raise TargetAuthError("copilot-config script tag not found in module page HTML")

        raw_json = match.group(1).strip()
        try:
            config: dict[str, Any] = json.loads(raw_json)
        except json.JSONDecodeError as exc:
            raise TargetAuthError(f"copilot-config JSON could not be parsed: {exc}") from exc

        jwt = config.get("jwt")
        if not isinstance(jwt, str) or not jwt:
            raise TargetAuthError("copilot-config JSON does not contain a 'jwt' field")

        self._jwt = jwt
        # The OpenEMR module emits camelCase keys (providerId, sessionId,
        # patientIds, providerName). Manifest §2B used snake_case which was
        # incorrect; the live module is camelCase. Accept either form so a
        # future module rename doesn't quietly break us.
        self._provider_id = config.get("providerId") or config.get("provider_id")
        self._session_id = config.get("sessionId") or config.get("session_id")
        provider_name = config.get("providerName") or config.get("provider_name")
        self._provider_name = provider_name if isinstance(provider_name, str) else "Provider"
        panel = config.get("patientIds") or config.get("patient_ids") or []
        self._panel_patient_ids = (
            [str(pid) for pid in panel] if isinstance(panel, list) else []
        )

        # Decode the exp claim (never log the full JWT).
        self._jwt_exp = self._decode_jwt_exp(jwt)

    @staticmethod
    def _decode_jwt_exp(jwt_str: str) -> float | None:
        """Decode the exp claim from a JWT payload without verifying signature."""
        import base64

        parts = jwt_str.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Add padding.
        padding = 4 - (len(payload_b64) % 4)
        if padding != 4:
            payload_b64 += "=" * padding
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload: dict[str, Any] = json.loads(payload_bytes)
            exp = payload.get("exp")
            return float(exp) if exp is not None else None
        except Exception:
            return None

    async def fire_query(
        self,
        *,
        message: str,
        attack_id: UUID,
        campaign_id: UUID,
        patient_ids: list[str],
        session_id: str | None = None,
    ) -> TargetResponse:
        """POST /agent/query with the cached Bearer JWT.

        Enforces the outbound rate limit BEFORE the request is sent.
        On 401 with reason=expired, re-authenticates once and retries.

        Args:
            message: The attack message text (treated as data, never as code).
            attack_id: UUID of the attack row being executed.
            campaign_id: UUID of the parent campaign (for rate-limit accounting).
            patient_ids: List of patient IDs to include in the request context.
            session_id: Optional session ID; defaults to the one obtained at
                authentication time.

        Returns:
            TargetResponse with the parsed response fields.

        Raises:
            TargetAuthError: If authentication fails or a re-auth retry fails.
            TargetUnavailableError: On 5xx or network errors.
            TargetRateLimitedError: On 429.
            TargetUnexpectedShapeError: If the response JSON shape is wrong.
        """
        await self._rate_limiter.acquire(campaign_id=campaign_id)

        message_hash = hashlib.sha256(message.encode()).hexdigest()[:16]
        log_event(
            "target_query_started",
            campaign_id=str(campaign_id),
            attack_id=str(attack_id),
            message_hash=message_hash,
            message_length=len(message),
        )

        try:
            response = await self._do_fire_query(
                message=message,
                attack_id=attack_id,
                campaign_id=campaign_id,
                patient_ids=patient_ids,
                session_id=session_id,
                is_retry=False,
            )
        except TargetAuthError:
            raise
        except Exception as exc:
            log_event(
                "target_query_failed",
                campaign_id=str(campaign_id),
                attack_id=str(attack_id),
                error_class=type(exc).__name__,
            )
            raise

        log_event(
            "target_query_finished",
            campaign_id=str(campaign_id),
            attack_id=str(attack_id),
            status_code=response.status_code,
            response_hash=hashlib.sha256(response.response_body.encode()).hexdigest()[:16],
            response_length=len(response.response_body),
            duration_ms=response.response_time_ms,
            outcome="success",
        )
        return response

    async def _do_fire_query(
        self,
        *,
        message: str,
        attack_id: UUID,
        campaign_id: UUID,
        patient_ids: list[str],
        session_id: str | None,
        is_retry: bool,
    ) -> TargetResponse:
        """Internal: make one POST /agent/query call.

        On 401 with reason=expired, re-authenticates and retries once.
        """
        if self._jwt is None:
            await self.authenticate()

        jwt = self._jwt
        if jwt is None:
            raise TargetAuthError("JWT is None after authenticate() — this should not happen")

        sid = session_id or self._session_id or ""
        provider_id = self._provider_id or ""
        # If the caller passed an empty patient_ids list, fall back to the
        # authenticated user's full panel — without at least one in-panel
        # ID, the dispatcher's pre-tool scope check fails open per the
        # manifest §3.5 design and we don't actually exercise the LLM.
        effective_patient_ids = patient_ids if patient_ids else self._panel_patient_ids

        body: dict[str, Any] = {
            "message": message,
            "session_id": sid,
            "provider_id": provider_id,
            "patient_ids": effective_patient_ids,
            "provider_name": self._provider_name,
        }

        http = self._require_http()
        start_ns = time.perf_counter_ns()

        try:
            resp = await http.post(
                f"{self._agent_api_url}/agent/query",
                json=body,
                headers={
                    # Authorization header is set here. The redaction layer in
                    # log_event() will strip it from any log that leaks it by key.
                    "Authorization": f"Bearer {jwt}",
                    "Content-Type": "application/json",
                },
            )
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            raise TargetUnavailableError(f"Agent API unreachable: {type(exc).__name__}") from exc

        elapsed_ms = (time.perf_counter_ns() - start_ns) // 1_000_000

        if resp.status_code == 429:
            raise TargetRateLimitedError("Agent API returned 429 — backing off")

        if resp.status_code >= 500:
            raise TargetUnavailableError(f"Agent API returned {resp.status_code}")

        # JWT expiry: one retry.
        if resp.status_code == 401 and not is_retry:
            reason = ""
            try:
                err_body = resp.json()
                reason = err_body.get("detail", {}).get("reason", "")
            except Exception:  # json decode or missing attr — safe to swallow
                reason = ""
            if reason == "expired":
                self._jwt = None
                await self.authenticate()
                return await self._do_fire_query(
                    message=message,
                    attack_id=attack_id,
                    campaign_id=campaign_id,
                    patient_ids=patient_ids,
                    session_id=session_id,
                    is_retry=True,
                )
            raise TargetAuthError(
                f"Agent API returned 401 (reason={reason!r}). "
                "Re-authentication is not expected to help for non-expired tokens."
            )

        if resp.status_code == 401 and is_retry:
            raise TargetAuthError(
                "Agent API returned 401 after re-authentication. "
                "Credentials may be invalid or the JWT secret rotated."
            )

        # Truncate response body to 100 kB.
        raw_body = resp.text[:_MAX_RESPONSE_BODY_BYTES]

        # Parse response shape: {narrative, data, citations, errors}
        narrative: str | None = None
        errors: list[str] = []
        if resp.status_code < 400:
            try:
                parsed: dict[str, Any] = resp.json()
                if not isinstance(parsed, dict):
                    raise TargetUnexpectedShapeError(
                        f"Expected JSON object, got {type(parsed).__name__}"
                    )
                narrative = parsed.get("narrative")
                raw_errors = parsed.get("errors", [])
                errors = [str(e) for e in raw_errors] if isinstance(raw_errors, list) else []
            except (json.JSONDecodeError, TargetUnexpectedShapeError):
                # Non-200 paths and malformed JSON are tolerated — we store the
                # raw body for the Judge to evaluate.
                pass

        # Strip Authorization header from response_headers before returning.
        safe_headers: dict[str, str] = {
            k: v
            for k, v in resp.headers.items()
            if k.lower() not in ("authorization", "set-cookie", "cookie")
        }

        return TargetResponse(
            status_code=resp.status_code,
            response_time_ms=int(elapsed_ms),
            response_body=raw_body,
            response_headers=safe_headers,
            narrative=narrative,
            errors=errors,
            attempted_at=datetime.now(UTC),
        )

    async def fire_multi_turn(
        self,
        *,
        turns: list[str],
        attack_id: UUID,
        campaign_id: UUID,
        patient_ids: list[str],
    ) -> list[TargetResponse]:
        """Send a multi-turn attack sequence, reusing the session_id.

        Each turn is rate-limited independently. The session_id obtained at
        authentication time is used for all turns so that the target's
        conversation checkpointer maintains context across turns.

        Args:
            turns: Ordered list of attack message strings.
            attack_id: UUID of the attack row (used for logging).
            campaign_id: UUID of the parent campaign.
            patient_ids: Patient IDs in scope for the session.

        Returns:
            List of TargetResponse, one per turn, in order.
        """
        responses: list[TargetResponse] = []
        for i, turn_message in enumerate(turns):
            log_event(
                "target_multi_turn_step",
                campaign_id=str(campaign_id),
                attack_id=str(attack_id),
                turn_index=i,
                total_turns=len(turns),
                message_hash=hashlib.sha256(turn_message.encode()).hexdigest()[:16],
                message_length=len(turn_message),
            )
            resp = await self.fire_query(
                message=turn_message,
                attack_id=attack_id,
                campaign_id=campaign_id,
                patient_ids=patient_ids,
                session_id=self._session_id,
            )
            responses.append(resp)
        return responses

    def _require_http(self) -> httpx.AsyncClient:
        """Return the httpx client. Raises RuntimeError if not inside a context."""
        if self._http is None:
            raise RuntimeError(
                "TargetClient must be used as an async context manager "
                "(async with TargetClient(...) as client:)"
            )
        return self._http
