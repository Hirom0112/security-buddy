"""LLM client package — single async wrapper around OpenRouter.

All LLM calls in Security Buddy go through LLMClient. This is the only
package in the codebase that holds the OpenRouter API key.

Architectural boundary (import-linter): this package does NOT import from
agents/ or repositories/. It is a leaf node.

Import from submodules directly to avoid circular imports:
    from src.llm_client.client import LLMClient
    from src.llm_client.types import Completion, Message
    from src.llm_client.redaction import redact
"""
