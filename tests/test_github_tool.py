import os

from tools import tool_implementations as tools


def _ticket():
    return tools.generate_ticket("Test finding", "Test body", "HIGH", "security-team")


def test_duplicate_issue_preserves_created_false(monkeypatch):
    monkeypatch.setenv("VULNAGENT_CREATE_GITHUB_ISSUES", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "ParnikaSarbahi/VulnAgent")

    class FakeClient:
        def create_issue(self, *args, **kwargs):
            return {"created": False, "duplicate": True, "issue_number": 7}

    monkeypatch.setattr(tools, "GitHubClient", FakeClient)

    result = _ticket()
    assert result["created"] is False
    assert result["duplicate"] is True
    assert result["issue_number"] == 7


def test_pr_comment_requires_pr_number(monkeypatch):
    monkeypatch.setenv("VULNAGENT_COMMENT_ON_PR", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "ParnikaSarbahi/VulnAgent")
    monkeypatch.delenv("GITHUB_PR_NUMBER", raising=False)

    result = _ticket()
    assert result["pr_comment_error"] == "GITHUB_PR_NUMBER is not configured"


def test_pr_comment_is_posted(monkeypatch):
    monkeypatch.setenv("VULNAGENT_COMMENT_ON_PR", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "ParnikaSarbahi/VulnAgent")
    monkeypatch.setenv("GITHUB_PR_NUMBER", "42")

    class FakeClient:
        def add_pr_comment(self, repository, pr_number, comment):
            assert repository == "ParnikaSarbahi/VulnAgent"
            assert pr_number == 42
            assert "VulnAgent Security Review" in comment
            return {"commented": True, "pr_number": pr_number}

    monkeypatch.setattr(tools, "GitHubClient", FakeClient)

    result = _ticket()
    assert result["pr_comment"]["commented"] is True
    assert result["pr_comment"]["pr_number"] == 42
