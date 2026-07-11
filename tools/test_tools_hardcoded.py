"""
test_tools_hardcoded.py

Tests each of the 4 tool implementations directly with hardcoded arguments
(as if the model had already decided on these values). This proves the
tool functions themselves work correctly, BEFORE we involve the LLM at
all. Isolating this from the LLM call means: if something breaks later,
we already know the tools themselves are solid, so the bug must be in
how we're calling the model or parsing its tool_calls.
"""

from tool_implementations import (
    classify_severity,
    suggest_remediation,
    generate_ticket,
    escalate_to_human,
)

print("=== Testing classify_severity ===")
result = classify_severity(
    severity="HIGH",
    cvss_score=8.1,
    business_impact="Allows arbitrary shell command execution if user input reaches this code path.",
    confidence=0.9,
)
print(result)
print()

print("=== Testing suggest_remediation ===")
result = suggest_remediation(
    fix_description="Avoid shell=True; pass command as a list and use subprocess.run with shell=False.",
    code_snippet="subprocess.run(['echo', user_input], shell=False)",
    reference_links=["https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_calls.html#b602"],
)
print(result)
print()

print("=== Testing generate_ticket ===")
result = generate_ticket(
    title="Shell injection risk in run_user_command()",
    body_markdown="**Severity:** HIGH\n\n**Location:** samples/vulnerable_app.py:17\n\n**Issue:** subprocess.call uses shell=True with unsanitized input.",
    priority="P1",
    assignee_placeholder="@security-team",
)
print(result)
print()

print("=== Testing escalate_to_human ===")
result = escalate_to_human(
    reason="Critical severity finding",
    context="Hardcoded credential found in connect_to_db(), needs immediate rotation.",
    urgency="IMMEDIATE",
)
print(result)
print()
print("Check reports/escalations_log.jsonl -- this escalation should now be logged there.")