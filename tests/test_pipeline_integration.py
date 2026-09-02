import json

from agent import agent_core
from scanners.finding_schema import Finding


def _finding(raw_severity="HIGH"):
    return Finding(
        id="bandit-0001",
        source="bandit",
        title="subprocess call with shell=True",
        description="Command execution can allow shell injection.",
        file_path="samples/vulnerable_app.py",
        line_number=17,
        raw_severity=raw_severity,
        cwe_id=78,
        code_snippet="subprocess.call(command, shell=True)",
    )


def _tool_response(arguments):
    return {
        "message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"arguments": arguments}}],
        }
    }


def test_full_auto_triage_flow(monkeypatch, tmp_path):
    calls = []
    responses = {
        "classify_severity": {
            "severity": "HIGH",
            "cvss_score": 8.1,
            "business_impact": "Remote command execution may compromise the application host.",
            "confidence_level": "HIGH",
        },
        "suggest_remediation": {
            "fix_description": "Avoid shell=True and pass arguments as a list with shell=False.",
            "code_snippet": "subprocess.run([\"safe-command\", arg], check=True)",
            "reference_links": [],
        },
        "generate_ticket": {
            "title": "[HIGH] Avoid shell=True command execution",
            "body_markdown": "Replace shell=True with a safe argument list.",
            "priority": "P1",
            "assignee_placeholder": "@security-team",
        },
    }

    def fake_chat(messages, tools=None):
        tool_name = tools[0]["function"]["name"]
        calls.append(tool_name)
        return _tool_response(responses[tool_name])

    monkeypatch.setattr(agent_core, "chat", fake_chat)
    monkeypatch.setenv("VULNAGENT_CREATE_GITHUB_ISSUES", "false")
    monkeypatch.setenv("VULNAGENT_COMMENT_ON_PR", "false")

    output = tmp_path / "results.json"
    results = agent_core.triage_all([_finding()], save_incrementally_to=str(output))

    assert len(results) == 1
    result = results[0]
    assert result["escalated"] is False
    assert result["iterations"] == 3
    assert [call["tool"] for call in result["tool_calls"]] == [
        "classify_severity",
        "suggest_remediation",
        "generate_ticket",
    ]
    assert result["tool_calls"][-1]["result"]["created"] is False
    assert calls == ["classify_severity", "suggest_remediation", "generate_ticket"]
    assert json.loads(output.read_text())[0]["finding_id"] == "bandit-0001"


def test_critical_finding_escalates_without_remediation(monkeypatch):
    calls = []

    def critical_chat(messages, tools=None):
        tool_name = tools[0]["function"]["name"]
        calls.append(tool_name)
        arguments = (
            {
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "business_impact": "Full compromise is plausible.",
                "confidence_level": "HIGH",
            }
            if tool_name == "classify_severity"
            else {
                "reason": "Critical severity requires human review.",
                "context": "Classification is CRITICAL.",
                "urgency": "HIGH",
            }
        )
        return _tool_response(arguments)

    monkeypatch.setattr(agent_core, "chat", critical_chat)
    result = agent_core.triage_finding(_finding())

    assert result["escalated"] is True
    assert [call["tool"] for call in result["tool_calls"]] == [
        "classify_severity",
        "escalate_to_human",
    ]
    assert calls == ["classify_severity", "escalate_to_human"]
