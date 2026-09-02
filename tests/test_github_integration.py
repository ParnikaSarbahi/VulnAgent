import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.tool_implementations import generate_ticket


def test_generate_ticket_is_draft_by_default(monkeypatch):
    monkeypatch.delenv("VULNAGENT_CREATE_GITHUB_ISSUES", raising=False)
    result = generate_ticket("Security issue", "Details", "P1", "@security-team")
    assert result["created"] is False
    assert "number" not in result


def test_generate_ticket_reports_missing_repository(monkeypatch):
    monkeypatch.setenv("VULNAGENT_CREATE_GITHUB_ISSUES", "true")
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    result = generate_ticket("Security issue", "Details", "P1", "@security-team")
    assert result["created"] is False
    assert "GITHUB_REPOSITORY" in result["error"]
