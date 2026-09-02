"""Small GitHub REST client used by VulnAgent for GitHub side effects."""

import os
from typing import Optional

import requests


class GitHubClient:
    def __init__(self, token: Optional[str] = None, api_url: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.api_url = (api_url or os.getenv("GITHUB_API_URL") or "https://api.github.com").rstrip("/")

    def _headers(self) -> dict:
        if not self.token:
            raise RuntimeError("GITHUB_TOKEN is not configured")
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, path: str, **kwargs):
        response = requests.request(
            method,
            f"{self.api_url}{path}",
            headers=self._headers(),
            timeout=20,
            **kwargs,
        )
        response.raise_for_status()
        return response.json()

    @staticmethod
    def finding_marker(title: str, body: str) -> str:
        """Return a stable marker used to make issue creation idempotent."""
        import hashlib
        digest = hashlib.sha256(f"{title}\n{body}".encode("utf-8")).hexdigest()[:16]
        return f"<!-- vulnagent-finding:{digest} -->"

    def find_existing_issue(self, repository: str, marker: str) -> Optional[dict]:
        """Find an open/closed issue previously generated for the same finding."""
        query = f'repo:{repository} is:issue "{marker}"'
        data = self._request("GET", "/search/issues", params={"q": query, "per_page": 10})
        items = data.get("items") or []
        if not items:
            return None
        issue = items[0]
        return {"number": issue.get("number"), "url": issue.get("html_url"), "api_url": issue.get("url")}

    def create_issue(self, repository: str, title: str, body: str, labels: Optional[list[str]] = None) -> dict:
        """Create an issue unless an identical VulnAgent finding already exists."""
        if not repository or repository.count("/") != 1:
            raise ValueError("repository must be in owner/name format")
        if not title or not title.strip():
            raise ValueError("issue title cannot be empty")

        marker = self.finding_marker(title, body)
        existing = self.find_existing_issue(repository, marker)
        if existing:
            existing["created"] = False
            existing["duplicate"] = True
            return existing

        body_with_marker = f"{marker}\n\n{body}"
        data = self._request(
            "POST",
            f"/repos/{repository}/issues",
            json={"title": title, "body": body_with_marker, "labels": labels or []},
        )
        return {
            "number": data.get("number"),
            "url": data.get("html_url"),
            "api_url": data.get("url"),
            "created": True,
            "duplicate": False,
        }

    def add_pr_comment(self, repository: str, pr_number: int, comment: str) -> dict:
        """Post a top-level conversation comment on a pull request."""
        if not isinstance(pr_number, int) or pr_number <= 0:
            raise ValueError("pr_number must be a positive integer")
        if not comment.strip():
            raise ValueError("comment cannot be empty")

        data = self._request(
            "POST",
            f"/repos/{repository}/issues/{pr_number}/comments",
            json={"body": comment},
        )
        return {"comment_id": data.get("id"), "url": data.get("html_url"), "created": True}
