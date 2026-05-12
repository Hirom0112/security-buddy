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
from uuid import UUID

import httpx

from src.llm_client.redaction import redact
from src.llm_client.types import AgentTag, Completion, Message, TokenUsage
from src.observability.context import get_request_id
from src.observability.events import log_event
from src.observability.metrics import LLM_CALL_DURATION, LLM_COST_TOTAL
from src.settings import Settings

_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
_DEFAULT_TIMEOUT = 60.0  # seconds


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class LLMClient:
    """Async wrapper around the OpenRouter chat completions API.

    Instantiate once per application lifecycle (inject via FastAPI Depends or
    pass through arq context). Do NOT create per-request instances.
    """

    def __init__(self, settings: Settings) -> None:
        self._api_key = settings.openrouter_api_key.get_secret_value()
        self._langsmith_disabled = settings.langsmith_disabled
        self._langsmith_api_key = settings.langsmith_api_key.get_secret_value()
        self._langsmith_project = settings.langsmith_project

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
        cost_usd = 0.0

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
                # OpenRouter returns cost in the usage object under "total_cost"
                # or as a response header x-openrouter-generation-cost.
                cost_usd = float(raw_usage.get("total_cost", 0.0))

            completion_hash = _sha256(completion_text) if completion_text else ""

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
                cost_usd=cost_usd,
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
    # Stubs — wired in later slices
    # ------------------------------------------------------------------

    async def _persist_trace(
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
        """Persist an agent_traces row to Postgres.

        # TODO(slice-0): wire to agent_traces table once schema is migrated.
        # The infra agent (or the Slice 1 database migration) creates the
        # agent_traces table; this method should then:
        #   async with session_factory() as session:
        #       session.add(AgentTraceORM(...))
        #       await session.commit()
        """
        # Redact the tag for safe logging, even though we only log hashes.
        _ = redact(tag.model_dump())  # validates redaction path; value not used yet

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
        """Emit a LangSmith span for this LLM call.

        No-ops if LANGSMITH_API_KEY is the literal "DISABLED".

        # TODO(slice-0): replace stub with real langsmith.Client().create_run()
        # call once the LangSmith project is validated in Slice 1+.
        """
        if self._langsmith_disabled:
            return
        # Real emit would use langsmith.Client(api_key=self._langsmith_api_key)
        # and create a run with the prompt_hash, completion_hash, usage, and tags.
        # Deferred to Slice 1 when we have a real campaign to trace.
