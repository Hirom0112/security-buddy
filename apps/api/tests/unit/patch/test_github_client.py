"""GitHubClient tests against a mocked httpx transport.

The Patch Agent never talks to real GitHub during unit tests. We mount an
httpx MockTransport so the request path, method, headers, and body schema
are all asserted in-process.
"""

from __future__ import annotations

import base64

import httpx
import pytest

from src.agents.patch.github_client import (
    CreatedPullRequest,
    GitHubClient,
    GitHubError,
)


def _ok(body: dict | str = "", status_code: int = 200) -> httpx.Response:
    if isinstance(body, dict):
        return httpx.Response(status_code, json=body)
    return httpx.Response(status_code, text=body)


@pytest.mark.asyncio
async def test_get_default_branch_sha_returns_sha() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/repos/owner/repo/git/ref/heads/main"
        assert "Bearer ghp-fake" in request.headers["authorization"]
        return _ok({"object": {"sha": "abc123"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        client = GitHubClient(token="ghp-fake", repo="owner/repo", http_client=c)
        sha = await client.get_default_branch_sha()
    assert sha == "abc123"


@pytest.mark.asyncio
async def test_create_branch_swallows_422_already_exists() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _ok({"message": "Reference already exists"}, status_code=422)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        client = GitHubClient(token="ghp-fake", repo="owner/repo", http_client=c)
        # Should not raise.
        await client.create_branch(branch="feature/x", from_sha="abc123")


@pytest.mark.asyncio
async def test_create_branch_raises_on_other_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return _ok({"message": "Forbidden"}, status_code=403)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        client = GitHubClient(token="ghp-fake", repo="owner/repo", http_client=c)
        with pytest.raises(GitHubError) as exc:
            await client.create_branch(branch="x", from_sha="abc")
        assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_put_file_creates_when_missing() -> None:
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "GET":
            return _ok({"message": "Not Found"}, status_code=404)
        body = request.read().decode()
        # PUT body should include base64-encoded contents and no `sha`.
        assert '"sha"' not in body
        assert base64.b64encode(b"hi").decode() in body
        return _ok({"commit": {"sha": "deadbeef"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        client = GitHubClient(token="ghp-fake", repo="owner/repo", http_client=c)
        sha = await client.put_file(
            branch="security-buddy/vul-0001",
            path="src/x.py",
            contents="hi",
            commit_message="fix: ...",
        )
    assert sha == "deadbeef"
    methods = [m for m, _ in calls]
    assert methods == ["GET", "PUT"]


@pytest.mark.asyncio
async def test_put_file_updates_when_existing() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return _ok({"sha": "oldsha", "encoding": "base64", "content": ""})
        body = request.read().decode()
        assert '"sha": "oldsha"' in body or '"sha":"oldsha"' in body
        return _ok({"commit": {"sha": "newsha"}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        client = GitHubClient(token="ghp-fake", repo="owner/repo", http_client=c)
        sha = await client.put_file(
            branch="security-buddy/vul-0001",
            path="src/x.py",
            contents="hi",
            commit_message="fix: ...",
        )
    assert sha == "newsha"


@pytest.mark.asyncio
async def test_open_pull_request_returns_parsed_struct() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read().decode()
        assert '"base": "main"' in body or '"base":"main"' in body
        return _ok(
            {
                "number": 42,
                "html_url": "https://github.com/owner/repo/pull/42",
                "head": {"ref": "security-buddy/vul-0001", "sha": "sha42"},
            }
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        client = GitHubClient(token="ghp-fake", repo="owner/repo", http_client=c)
        pr: CreatedPullRequest = await client.open_pull_request(
            branch="security-buddy/vul-0001",
            title="title",
            body="body",
        )
    assert pr.number == 42
    assert pr.html_url.endswith("/42")
    assert pr.head_sha == "sha42"


def test_invalid_repo_slug_raises() -> None:
    with pytest.raises(ValueError):
        GitHubClient(token="x", repo="not-a-slash")
