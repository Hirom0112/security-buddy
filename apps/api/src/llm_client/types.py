"""Pydantic models for LLM client request and response types."""

from uuid import UUID

from pydantic import BaseModel, Field


class Message(BaseModel):
    """A single chat message in OpenRouter format."""

    role: str = Field(description="One of: system, user, assistant")
    content: str = Field(description="Message text")


class TokenUsage(BaseModel):
    """Token usage from an OpenRouter completion."""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class Completion(BaseModel):
    """Parsed OpenRouter chat completion response."""

    model: str = Field(description="The model that produced this completion")
    content: str = Field(description="The assistant's reply text")
    usage: TokenUsage
    cost_usd: float = Field(
        description="Estimated cost in USD (from OpenRouter x-cost header or usage*rate)",
        ge=0.0,
    )
    duration_ms: float = Field(description="Wall-clock time for the HTTP call in ms", ge=0.0)
    prompt_hash: str = Field(description="SHA-256 hex digest of the serialized prompt")
    completion_hash: str = Field(description="SHA-256 hex digest of the completion content")


class AgentTag(BaseModel):
    """Tracing tags attached to every LLM call."""

    agent: str = Field(description="Agent name (orchestrator|red_team|judge|documentation|patch)")
    request_id: str | None = Field(default=None)
    campaign_id: UUID | None = Field(default=None)
    attack_id: UUID | None = Field(default=None)
    verdict_id: UUID | None = Field(default=None)
