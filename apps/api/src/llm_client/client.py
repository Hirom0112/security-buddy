"""Async OpenRouter LLM client.

Every LLM call in Security Buddy goes through LLMClient.complete().
The client:
  1. Calls OpenRouter via httpx.AsyncClient
  2. Tags every call with agent, request_id (from ContextVar), and FK IDs
  3. Records prompt_hash + completion_hash (sha256), token counts, cost, duration
  4. Writes an agent_traces row (stubbed — wired in Slice 1 when schema exists)
  5. Emits a LangSmith span (no-ops when DISABLED)
  6. Emits llm_call_started and llm_call_finished structured log events
  7. NEVER logs raw prompt or completion text — only hashes, lengths, IDs

Security rules (CLAUDE.md §2):
  - API key read from settings — no fallback
  - Secrets redacted from all log output via redact()
"""

import hashlib
import json
import time
from decimal import Decimal
from typing import TYPE_CHECKING
from uuid import UUID

import httpx
import sqlalchemy as sa

from src.llm_client.pricing import compute_cost_usd
from src.llm_client.redaction import redact
from src.llm_client.types import AgentTag, Completion, Message, TokenUsage
from src.observability.context import get_request_id
from src.observability.events import log_event
from src.observability.metrics import LLM_CALL_DURATION, LLM_COST_TOTAL
from src.settings import Settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
_DEFAULT_TIMEOUT = 60.0  # seconds


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class LLMClient:
    """Async wrapper around the OpenRouter chat completions API.

    Instantiate once per application lifecycle (inject via FastAPI Depends or
    pass through arq context). Do NOT create per-request instances.
    """

    def __init__(
        self,
        settings: Settings,
        session_factory: "async_sessionmaker[AsyncSession] | None" = None,
    ) -> None:
        self._api_key = settings.openrouter_api_key.get_secret_value()
        self._langsmith_disabled = settings.langsmith_disabled
        self._langsmith_api_key = settings.langsmith_api_key.get_secret_value()
        self._langsmith_project = settings.langsmith_project
        self._session_factory = session_factory

        # Lazy-instantiate the LangSmith client. None when disabled or import fails.
        self._langsmith_client: object | None = None
        if not self._langsmith_disabled:
            try:
                from langsmith import Client as _LangsmithClient

                self._langsmith_client = _LangsmithClient(
                    api_key=self._langsmith_api_key
                )
            except Exception as exc:
                log_event(
                    "langsmith_client_init_failed",
                    outcome="failure",
                    error_type=type(exc).__name__,
                )

    async def complete(
        self,
        model: str,
        messages: list[Message],
        *,
        agent: str,
        campaign_id: UUID | None = None,
        attack_id: UUID | None = None,
        verdict_id: UUID | None = None,
    ) -> Completion:
        """Call the OpenRouter chat completions API.

        Args:
            model:       OpenRouter model identifier (e.g. "anthropic/claude-sonnet-4-5").
            messages:    Ordered list of chat messages.
            agent:       Calling agent name for tagging and cost attribution.
            campaign_id: FK for agent_traces.campaign_id (None if not in a campaign).
            attack_id:   FK for agent_traces.attack_id (None if not evaluating an attack).
            verdict_id:  FK for agent_traces.verdict_id (None if not in a verdict context).

        Returns:
            Completion model with content, usage, cost, hashes, and duration.

        Raises:
            httpx.HTTPStatusError: on non-2xx OpenRouter response.
            httpx.TimeoutException: if the call exceeds _DEFAULT_TIMEOUT seconds.
        """
        tag = AgentTag(
            agent=agent,
            request_id=get_request_id(),
            campaign_id=campaign_id,
            attack_id=attack_id,
            verdict_id=verdict_id,
        )

        prompt_str = json.dumps([m.model_dump() for m in messages], sort_keys=True)
        prompt_hash = _sha256(prompt_str)

        log_event(
            "llm_call_started",
            model=model,
            agent=agent,
            prompt_hash=prompt_hash,
            prompt_len=len(prompt_str),
            campaign_id=str(campaign_id) if campaign_id else None,
            attack_id=str(attack_id) if attack_id else None,
            verdict_id=str(verdict_id) if verdict_id else None,
        )

        start = time.monotonic()
        outcome = "success"
        completion_text = ""
        usage = TokenUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0)
        cost_decimal: Decimal = Decimal("0")

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.post(
                    f"{_OPENROUTER_BASE}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://github.com/security-buddy",
                        "X-Title": "Security Buddy",
                    },
                    json={
                        "model": model,
                        "messages": [m.model_dump() for m in messages],
                    },
                )
                resp.raise_for_status()
                data = resp.json()

        except Exception:
            outcome = "failure"
            raise

        finally:
            duration_ms = (time.monotonic() - start) * 1000

            if outcome == "success" and "choices" in locals().get("data", {}):
                completion_text = data["choices"][0]["message"]["content"] or ""
                raw_usage = data.get("usage", {})
                usage = TokenUsage(
                    prompt_tokens=raw_usage.get("prompt_tokens", 0),
                    completion_tokens=raw_usage.get("completion_tokens", 0),
                    total_tokens=raw_usage.get("total_tokens", 0),
                )
                # OpenRouter returns cost in the usage object under "total_cost",
                # but for some models (notably anthropic/claude-sonnet-4.6) it
                # returns 0 even when tokens are billed. Prefer the upstream
                # value when non-zero, otherwise compute from our hardcoded
                # rate table (src/llm_client/pricing.py).
                raw_cost = Decimal(str(raw_usage.get("total_cost", 0) or 0))
                if raw_cost > 0:
                    cost_decimal = raw_cost
                else:
                    cost_decimal = compute_cost_usd(
                        model,
                        tokens_in=usage.prompt_tokens,
                        tokens_out=usage.completion_tokens,
                    )

            completion_hash = _sha256(completion_text) if completion_text else ""
            cost_usd = float(cost_decimal)

            log_event(
                "llm_call_finished",
                model=model,
                agent=agent,
                prompt_hash=prompt_hash,
                completion_hash=completion_hash,
                completion_len=len(completion_text),
                tokens_in=usage.prompt_tokens,
                tokens_out=usage.completion_tokens,
                cost_usd=cost_usd,
                duration_ms=round(duration_ms, 2),
                outcome=outcome,
                campaign_id=str(campaign_id) if campaign_id else None,
                attack_id=str(attack_id) if attack_id else None,
                verdict_id=str(verdict_id) if verdict_id else None,
            )

            # Prometheus instrumentation
            LLM_COST_TOTAL.labels(agent=agent, model=model).inc(cost_usd)
            LLM_CALL_DURATION.labels(agent=agent, model=model).observe(duration_ms / 1000)

            # Trace persistence and LangSmith — stubs for Slice 0
            await self._persist_trace(
                tag=tag,
                model=model,
                prompt_hash=prompt_hash,
                completion_hash=completion_hash,
                usage=usage,
                cost_decimal=cost_decimal,
                duration_ms=duration_ms,
                outcome=outcome,
            )
            self._emit_langsmith_span(
                tag=tag,
                model=model,
                prompt_hash=prompt_hash,
                completion_hash=completion_hash,
                usage=usage,
                cost_usd=cost_usd,
                duration_ms=duration_ms,
                outcome=outcome,
            )

        result = Completion(
            model=model,
            content=completion_text,
            usage=usage,
            cost_usd=cost_usd,
            duration_ms=round(duration_ms, 2),
            prompt_hash=prompt_hash,
            completion_hash=completion_hash,
        )
        return result

    # ------------------------------------------------------------------
    # Persistence + tracing — best-effort, never fatal
    # ------------------------------------------------------------------

    async def _persist_trace(
        self,
        *,
        tag: AgentTag,
        model: str,
        prompt_hash: str,
        completion_hash: str,
        usage: TokenUsage,
        cost_decimal: Decimal,
        duration_ms: float,
        outcome: str,
    ) -> None:
        """Insert one agent_traces row. No-ops when no session_factory was injected
        (e.g. eval scripts running standalone). Failures are logged, never raised —
        the LLM call itself has already succeeded by this point.
        """
        _ = redact(tag.model_dump())  # validates redaction path

        if self._session_factory is None:
            return

        try:
            async with self._session_factory() as session:
                await session.execute(
                    sa.text(
                        "INSERT INTO agent_traces ("
                        "  agent, request_id, model, prompt_hash, completion_hash,"
                        "  tokens_in, tokens_out, cost_usd, duration_ms, outcome,"
                        "  campaign_id, attack_id, verdict_id"
                        ") VALUES ("
                        "  :agent, :request_id, :model, :prompt_hash, :completion_hash,"
                        "  :tokens_in, :tokens_out, :cost_usd, :duration_ms, :outcome,"
                        "  :campaign_id, :attack_id, :verdict_id"
                        ")"
                    ),
                    {
                        "agent": tag.agent,
                        "request_id": tag.request_id,
                        "model": model,
                        "prompt_hash": prompt_hash,
                        "completion_hash": completion_hash or None,
                        "tokens_in": usage.prompt_tokens,
                        "tokens_out": usage.completion_tokens,
                        "cost_usd": cost_decimal,
                        "duration_ms": round(duration_ms),
                        "outcome": outcome,
                        "campaign_id": str(tag.campaign_id) if tag.campaign_id else None,
                        "attack_id": str(tag.attack_id) if tag.attack_id else None,
                        "verdict_id": str(tag.verdict_id) if tag.verdict_id else None,
                    },
                )
                await session.commit()
        except Exception as exc:
            log_event(
                "agent_trace_persist_failed",
                agent=tag.agent,
                model=model,
                outcome="failure",
                error_type=type(exc).__name__,
            )

    def _emit_langsmith_span(
        self,
        *,
        tag: AgentTag,
        model: str,
        prompt_hash: str,
        completion_hash: str,
        usage: TokenUsage,
        cost_usd: float,
        duration_ms: float,
        outcome: str,
    ) -> None:
        """Create a LangSmith run for this LLM call.

        No-ops when LANGSMITH_API_KEY is "DISABLED" or the client failed to
        instantiate. Failures are logged, never raised.

        Inputs/outputs carry hashes only — never raw prompt or completion text.
        """
        if self._langsmith_client is None:
            return

        try:
            self._langsmith_client.create_run(  # type: ignore[attr-defined]
                name=f"llm.{tag.agent}",
                run_type="llm",
                inputs={"prompt_hash": prompt_hash, "model": model},
                outputs={
                    "completion_hash": completion_hash or None,
                    "tokens_in": usage.prompt_tokens,
                    "tokens_out": usage.completion_tokens,
                    "cost_usd": cost_usd,
                },
                extra={
                    "metadata": {
                        "agent": tag.agent,
                        "model": model,
                        "request_id": tag.request_id,
                        "campaign_id": str(tag.campaign_id) if tag.campaign_id else None,
                        "attack_id": str(tag.attack_id) if tag.attack_id else None,
                        "verdict_id": str(tag.verdict_id) if tag.verdict_id else None,
                        "duration_ms": duration_ms,
                        "outcome": outcome,
                    },
                    "tags": [f"agent:{tag.agent}", f"model:{model}"],
                },
                project_name=self._langsmith_project,
            )
        except Exception as exc:
            log_event(
                "langsmith_emit_failed",
                agent=tag.agent,
                model=model,
                outcome="failure",
                error_type=type(exc).__name__,
            )
