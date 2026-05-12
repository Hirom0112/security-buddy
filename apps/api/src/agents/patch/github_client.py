"""Thin async GitHub REST client for the Patch Agent.

Scope is deliberately tiny: just enough to (1) read a file at the default
branch, (2) create a branch from main, (3) create or update a file on that
branch, (4) open a pull request. No PyGithub, no octokit — those bring
transitive deps we don't need.

Architectural boundary (import-linter):
  agents/patch/ may import llm_client/ and observability/; it does NOT
  import other agents.

Authentication:
  The PAT is read from Settings.github_pat at construction time. It is
  scoped to the OpenEMR fork only (verified in CLAUDE.md §5 deliverable
  list). No log line in this module logs the token.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

import httpx

from src.observability.events import log_event

_GITHUB_API = "https://api.github.com"
_DEFAULT_TIMEOUT = 30.0


class GitHubError(RuntimeError):
    """Raised on a non-2xx response from the GitHub API."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"GitHub API error {status_code}: {message}")
        self.status_code = status_code


@dataclass(frozen=True)
class CreatedPullRequest:
    """Result of open_pull_request — what the worker writes to patches."""

    number: int
    html_url: str
    head_branch: str
    head_sha: str


class GitHubClient:
    """Async REST client for one specific OpenEMR fork.

    Holds the repo slug ("owner/name") and a PAT. Instances are cheap; one
    per call site is fine. Connection pooling is per-request (the worker
    only runs a handful of GitHub calls per job).
    """

    def __init__(
        self,
        *,
        token: str,
        repo: str,
        default_branch: str = "main",
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if "/" not in repo:
            raise ValueError(
                "repo must be in 'owner/name' form; got: " + repo
            )
        self._token = token
        self._repo = repo
        self._default_branch = default_branch
        self._client = http_client  # injected for tests; None → per-call

    @property
    def repo(self) -> str:
        return self._repo

    @property
    def default_branch(self) -> str:
        return self._default_branch

    # ------------------------------------------------------------------
    # Low-level request helper
    # ------------------------------------------------------------------
    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, object] | None = None,
    ) -> dict[str, object]:
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "security-buddy-patch-agent",
        }
        url = f"{_GITHUB_API}{path}"

        async def _do(client: httpx.AsyncClient) -> dict[str, object]:
            resp = await client.request(method, url, headers=headers, json=json)
            if resp.status_code >= 400:
                # Log status + path only; the body may echo our PR text but
                # never the PAT (auth header isn't reflected).
                log_event(
                    "github_request_failed",
                    method=method,
                    path=path,
                    status=resp.status_code,
                    outcome="failure",
                )
                raise GitHubError(resp.status_code, resp.text[:500])
            if resp.status_code == 204 or not resp.content:
                return {}
            data: dict[str, object] = resp.json()
            return data

        if self._client is not None:
            return await _do(self._client)
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            return await _do(client)

    # ------------------------------------------------------------------
    # High-level operations the Patch Agent needs
    # ------------------------------------------------------------------
    async def get_default_branch_sha(self) -> str:
        """Return the head commit SHA of the default branch."""
        ref_path = f"/repos/{self._repo}/git/ref/heads/{self._default_branch}"
        data = await self._request("GET", ref_path)
        obj = data.get("object")
        if not isinstance(obj, dict):
            raise GitHubError(500, "ref response missing 'object'")
        return str(obj.get("sha", ""))

    async def get_file(self, *, path: str, ref: str | None = None) -> str | None:
        """Return the file contents at `path` on `ref` (default: default_branch).

        Returns None if the file does not exist. Decodes base64.
        """
        url_path = f"/repos/{self._repo}/contents/{path}"
        if ref is not None:
            url_path += f"?ref={ref}"
        try:
            data = await self._request("GET", url_path)
        except GitHubError as exc:
            if exc.status_code == 404:
                return None
            raise
        if data.get("encoding") != "base64":
            return None
        content_field = data.get("content")
        if not isinstance(content_field, str):
            return None
        return base64.b64decode(content_field).decode("utf-8", errors="replace")

    async def create_branch(self, *, branch: str, from_sha: str) -> None:
        """Create a branch ref pointing at `from_sha`. No-op if it exists."""
        path = f"/repos/{self._repo}/git/refs"
        try:
            await self._request(
                "POST",
                path,
                json={"ref": f"refs/heads/{branch}", "sha": from_sha},
            )
        except GitHubError as exc:
            if exc.status_code == 422:  # already exists
                return
            raise

    async def put_file(
        self,
        *,
        branch: str,
        path: str,
        contents: str,
        commit_message: str,
    ) -> str:
        """Create or update one file on `branch`. Returns the resulting commit SHA.

        Uses the Contents API which auto-creates a commit per file. For
        multi-file patches the worker calls this once per file.
        """
        url_path = f"/repos/{self._repo}/contents/{path}"

        existing_sha: str | None = None
        try:
            data = await self._request("GET", f"{url_path}?ref={branch}")
            sha_field = data.get("sha")
            if isinstance(sha_field, str):
                existing_sha = sha_field
        except GitHubError as exc:
            if exc.status_code != 404:
                raise

        body: dict[str, object] = {
            "message": commit_message,
            "branch": branch,
            "content": base64.b64encode(contents.encode("utf-8")).decode("ascii"),
        }
        if existing_sha is not None:
            body["sha"] = existing_sha

        result = await self._request("PUT", url_path, json=body)
        commit = result.get("commit")
        if isinstance(commit, dict):
            sha = commit.get("sha", "")
            return str(sha) if isinstance(sha, str) else ""
        return ""

    async def open_pull_request(
        self,
        *,
        branch: str,
        title: str,
        body: str,
    ) -> CreatedPullRequest:
        """Open a PR from `branch` → default_branch."""
        path = f"/repos/{self._repo}/pulls"
        data = await self._request(
            "POST",
            path,
            json={
                "title": title,
                "body": body,
                "head": branch,
                "base": self._default_branch,
                "maintainer_can_modify": True,
            },
        )
        head_obj = data.get("head") if isinstance(data.get("head"), dict) else {}
        head: dict[str, object] = head_obj if isinstance(head_obj, dict) else {}
        number_field = data.get("number")
        if not isinstance(number_field, int):
            raise GitHubError(500, "PR response missing 'number'")
        return CreatedPullRequest(
            number=number_field,
            html_url=str(data.get("html_url", "")),
            head_branch=str(head.get("ref", branch)),
            head_sha=str(head.get("sha", "")),
        )
