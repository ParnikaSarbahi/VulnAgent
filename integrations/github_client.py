"""Small GitHub REST client used by VulnAgent for issue creation.

The token is read from the environment and is never logged. The client is
kept separate from the agent tools so GitHub side effects are easy to test
and can be disabled when running locally.
"""

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

    def create_issue(self, repository: str, title: str, body: str, labels: Optional[list[str]] = None) -> dict:
        """Create one GitHub issue and return its basic metadata."""
        if not repository or "/" not in repository:
            raise ValueError("repository must be in owner/name format")
        if not title.strip():
            raise ValueError("issue title cannot be empty")

        response = requests.post(
            f"{self.api_url}/repos/{repository}/issues",
            headers=self._headers(),
            json={"title": title, "body": body, "labels": labels or []},
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        return {
            "number": data.get("number"),
            "url": data.get("html_url"),
            "api_url": data.get("url"),
        }
