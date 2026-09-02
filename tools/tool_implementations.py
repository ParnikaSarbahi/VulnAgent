"""
tool_implementations.py

Reliable executors for the tools exposed to the local LLM. The model supplies
security judgments and ticket content; these functions validate, structure,
and persist the resulting actions.
"""

import json
import os
from datetime import datetime, timezone

from integrations.github_client import GitHubClient
from integrations.pr_comment import build_pr_comment

ESCALATIONS_LOG = os.path.join(os.path.dirname(__file__), "..", "reports", "escalations_log.jsonl")


def _coerce_float(value, default=0.0):
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


CONFIDENCE_LEVEL_MAP = {"LOW": 0.25, "MEDIUM": 0.6, "HIGH": 0.9}


def classify_severity(severity, cvss_score, business_impact, confidence_level):
    confidence_level = str(confidence_level).upper()
    return {
        "severity": severity,
        "cvss_score": _coerce_float(cvss_score),
        "business_impact": business_impact,
        "confidence_level": confidence_level,
        "confidence": CONFIDENCE_LEVEL_MAP.get(confidence_level, 0.5),
    }


def suggest_remediation(fix_description, code_snippet, reference_links):
    if isinstance(reference_links, str):
        links_list = [link.strip() for link in reference_links.split(",") if link.strip()]
    elif isinstance(reference_links, list):
        links_list = reference_links
    else:
        links_list = []
    return {
        "fix_description": fix_description,
        "code_snippet": code_snippet,
        "reference_links": links_list,
    }


def generate_ticket(title, body_markdown, priority, assignee_placeholder):
    """Create a draft and optionally file a GitHub issue or PR comment."""
    result = {
        "title": title,
        "body_markdown": body_markdown,
        "priority": priority,
        "assignee_placeholder": assignee_placeholder,
        "created": False,
    }

    if os.getenv("VULNAGENT_CREATE_GITHUB_ISSUES", "false").lower() == "true":
        repository = os.getenv("GITHUB_REPOSITORY")
        if not repository:
            result["error"] = "GITHUB_REPOSITORY is not configured"
        else:
            try:
                labels = ["security", priority.lower()]
                issue_result = GitHubClient().create_issue(repository, title, body_markdown, labels=labels)
                result.update(issue_result)
            except Exception as exc:
                result["error"] = str(exc)

    if os.getenv("VULNAGENT_COMMENT_ON_PR", "false").lower() == "true":
        repository = os.getenv("GITHUB_REPOSITORY")
        pr_number = os.getenv("GITHUB_PR_NUMBER")
        if not repository:
            result["pr_comment_error"] = "GITHUB_REPOSITORY is not configured"
        elif not pr_number:
            result["pr_comment_error"] = "GITHUB_PR_NUMBER is not configured"
        else:
            try:
                comment = build_pr_comment(
                    [{"finding_title": title, "finding_source": "VulnAgent", "tool_calls": [], "escalated": False}],
                    int(pr_number),
                )
                result["pr_comment"] = GitHubClient().add_pr_comment(repository, int(pr_number), comment)
            except (TypeError, ValueError) as exc:
                result["pr_comment_error"] = f"Invalid GITHUB_PR_NUMBER: {exc}"
            except Exception as exc:
                result["pr_comment_error"] = str(exc)

    return result


def escalate_to_human(reason, context, urgency):
    result = {
        "reason": reason,
        "context": context,
        "urgency": urgency,
        "escalated_at": datetime.now(timezone.utc).isoformat(),
    }
    os.makedirs(os.path.dirname(ESCALATIONS_LOG), exist_ok=True)
    with open(ESCALATIONS_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(result) + "\n")
    return result


TOOL_DISPATCH = {
    "classify_severity": classify_severity,
    "suggest_remediation": suggest_remediation,
    "generate_ticket": generate_ticket,
    "escalate_to_human": escalate_to_human,
}
