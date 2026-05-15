"""POST /webhooks/github — receive merge notifications from the OpenEMR fork.

Verifies the HMAC-SHA256 signature in X-Hub-Signature-256 against
SETTINGS.github_webhook_secret. Fail-closed: if the secret is unset, every
delivery is rejected.

Slice 3 scope:
  - Verify signature.
  - Identify pull_request 'closed' + merged=true events.
  - For now, log and enqueue a placeholder — Slice 6 wires this to the
    regression harness. The webhook contract is finalized here so the
    operator can configure the GitHub webhook once and forget.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from src.domain.patch import PatchStatus
from src.observability.context import get_request_id
from src.observability.events import log_event
from src.repositories.patches import PatchRepository
from src.settings import Settings, get_settings
from src.workers.queue import enqueue_harness_regression_sweep

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _get_settings() -> Settings:
    """FastAPI dependency wrapper for the lru-cached settings singleton."""
    return get_settings()


def _verify_signature(
    *,
    secret: bytes,
    body: bytes,
    header_value: str,
) -> bool:
    """Constant-time verify the X-Hub-Signature-256 header.

    GitHub sends the header as 'sha256=<hex>'. Any deviation (wrong scheme,
    truncated, missing) → False.
    """
    if not header_value.startswith("sha256="):
        return False
    expected_hex = hmac.new(secret, body, hashlib.sha256).hexdigest()
    provided_hex = header_value.removeprefix("sha256=")
    return hmac.compare_digest(expected_hex, provided_hex)


@router.post(
    "/github",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Receive GitHub webhook (merge → regression queue)",
)
async def github_webhook(
    request: Request,
    settings: Annotated[Settings, Depends(_get_settings)],
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    # ------------------------------------------------------------------
    # Fail-closed: no secret configured → no webhook acceptance.
    # ------------------------------------------------------------------
    if settings.github_webhook_secret is None:
        log_event(
            "github_webhook_rejected",
            reason="secret_unset",
            outcome="rejected",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="webhook secret not configured",
        )

    if x_hub_signature_256 is None:
        log_event(
            "github_webhook_rejected",
            reason="missing_signature_header",
            outcome="rejected",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing signature header",
        )

    body = await request.body()
    secret_bytes = settings.github_webhook_secret.get_secret_value().encode()
    if not _verify_signature(secret=secret_bytes, body=body, header_value=x_hub_signature_256):
        log_event(
            "github_webhook_rejected",
            reason="bad_signature",
            outcome="rejected",
            event=x_github_event,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="signature mismatch",
        )

    payload = await request.json()

    # ------------------------------------------------------------------
    # We only act on merged PRs. Other events are acknowledged 202 and
    # logged. ping events are acknowledged too so GitHub's webhook
    # diagnostic page shows green.
    # ------------------------------------------------------------------
    if x_github_event == "ping":
        log_event("github_webhook_ping", outcome="acknowledged")
        return {"status": "pong"}

    if x_github_event != "pull_request":
        log_event(
            "github_webhook_ignored",
            event=x_github_event,
            outcome="ignored",
        )
        return {"status": "ignored", "reason": f"event={x_github_event}"}

    action = payload.get("action")
    pr = payload.get("pull_request") or {}
    merged = bool(pr.get("merged"))
    if action != "closed" or not merged:
        log_event(
            "github_webhook_ignored",
            event=x_github_event,
            action=action,
            merged=merged,
            outcome="ignored",
        )
        return {"status": "ignored", "reason": "not a merged-PR event"}

    pr_number = pr.get("number")
    sha = (pr.get("merge_commit_sha") or "").strip() or None
    base_ref = (pr.get("base") or {}).get("ref")
    head_branch = ((pr.get("head") or {}).get("ref") or "").strip() or None

    # Slice 5: locate the Patch row by head branch name and flip it to merged.
    # Slice 6 enqueues the regression worker on the same path.
    patch_id: str | None = None
    factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    if head_branch is not None:
        async with factory() as session:
            try:
                repo = PatchRepository()
                patch = await repo.get_by_branch_name(session, head_branch)
                if patch is not None and patch.status is PatchStatus.AWAITING_HUMAN_REVIEW:
                    updated = await repo.update_status(
                        session,
                        patch_id=patch.id,
                        new_status=PatchStatus.MERGED,
                        merged_at_sql=True,
                    )
                    if updated is not None:
                        patch_id = str(updated.id)
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    # Slice 6: enqueue the regression sweep against the new target version.
    # We pass merge_commit_sha as the version hint; the worker upserts a
    # target_versions row keyed on the active manifest's target_id.
    version_hint = sha or "unknown"
    request_id = get_request_id() or "webhook"
    await enqueue_harness_regression_sweep(
        target_version_hint=version_hint,
        triggered_by="github_merge",
        request_id=request_id,
    )

    log_event(
        "github_webhook_accepted",
        event=x_github_event,
        pr_number=pr_number,
        merge_commit_sha=sha,
        base_ref=base_ref,
        head_branch=head_branch,
        patch_id=patch_id,
        outcome="accepted",
    )

    return {
        "status": "accepted",
        "pr_number": pr_number,
        "merge_commit_sha": sha,
        "patch_id": patch_id,
        "regression_sweep": "enqueued",
    }
