"""
agent_core.py

Deterministic orchestration for VulnAgent's vulnerability triage pipeline.
The Python layer controls workflow order while the local LLM supplies the
security assessment and remediation content.
"""

import json
import os

from agent.ollama_client import chat
from scanners.deduplicator import deduplicate_findings
from tools.tool_definitions import TOOLS
from tools.tool_implementations import TOOL_DISPATCH

MAX_ITERATIONS = 6
CONFIDENCE_THRESHOLD = 0.5

SYSTEM_PROMPT = """You are a security triage agent. You will be asked to call specific tools one at a time. Base every field on the specific finding. cvss_score must be 0.0-10.0. confidence_level must be LOW, MEDIUM, or HIGH. business_impact must describe this finding specifically. Severity is about impact if exploited. Call only the tool you are asked to call."""


def _finding_to_prompt(finding):
    return (
        f"Triage this vulnerability finding:\n"
        f"Source: {finding.source}\nTitle: {finding.title}\n"
        f"Description: {finding.description}\nFile: {finding.file_path}, line {finding.line_number}\n"
        f"Scanner's own severity label: {finding.raw_severity}\nCWE ID: {finding.cwe_id}\n"
        f"Code:\n{finding.code_snippet}"
    )


def _extract_fallback_tool_call(message, expected_tool_name):
    content = message.get("content", "")
    if not content:
        return None
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        repaired = content.replace('}"}', '}}').replace("}'}", "}}")
        try:
            parsed = json.loads(repaired)
        except (json.JSONDecodeError, TypeError):
            return None
    if not isinstance(parsed, dict):
        return None
    name = parsed.get("name")
    args = parsed.get("parameters") or parsed.get("arguments")
    if name == expected_tool_name and isinstance(args, dict):
        return args
    return None


def _call_single_tool(messages, tool_name, instruction=None):
    tool_def = next(t for t in TOOLS if t["function"]["name"] == tool_name)
    call_messages = messages + ([{"role": "user", "content": instruction}] if instruction else [])
    response = chat(call_messages, tools=[tool_def])
    message = response["message"]
    tool_calls = message.get("tool_calls")
    args = tool_calls[0]["function"]["arguments"] if tool_calls else _extract_fallback_tool_call(message, tool_name)
    if args is None:
        return None, message
    try:
        result = TOOL_DISPATCH[tool_name](**args)
    except TypeError as e:
        result = {"error": f"Bad arguments for {tool_name}: {e}"}
    return {"tool": tool_name, "arguments": args, "result": result}, message


def triage_finding(finding):
    base_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _finding_to_prompt(finding)},
    ]
    tool_call_log = []
    escalated = False

    call_record, model_message = _call_single_tool(base_messages, "classify_severity")
    if call_record is None:
        escalate_record, _ = _call_single_tool(
            base_messages + [{"role": "user", "content": "Escalate this finding: classification failed."}],
            "escalate_to_human",
        )
        if escalate_record:
            tool_call_log.append(escalate_record)
        return {"finding_id": finding.id, "finding_title": finding.title, "finding_source": finding.source,
                "tool_calls": tool_call_log, "escalated": True, "iterations": 1}

    tool_call_log.append(call_record)
    classification = call_record["result"]
    conversation = base_messages + [model_message, {"role": "tool", "content": json.dumps(classification)}]
    severity = str(classification.get("severity", "")).upper()
    confidence = classification.get("confidence", 0.0)

    if severity == "CRITICAL" or confidence < CONFIDENCE_THRESHOLD:
        escalate_record, _ = _call_single_tool(
            conversation, "escalate_to_human",
            instruction="Now call escalate_to_human to escalate this specific finding, using the classification above as context.",
        )
        if escalate_record:
            tool_call_log.append(escalate_record)
        else:
            fallback_result = TOOL_DISPATCH["escalate_to_human"](
                reason=f"Escalation triggered ({'CRITICAL severity' if severity == 'CRITICAL' else 'low confidence'}), but model failed to generate escalation details",
                context=f"Classification: {json.dumps(classification)}",
                urgency="HIGH" if severity == "CRITICAL" else "MEDIUM",
            )
            tool_call_log.append({"tool": "escalate_to_human", "arguments": "FALLBACK -- model failed to call this tool", "result": fallback_result})
        escalated = True
        iterations = 2
    else:
        remediation_record, remediation_message = _call_single_tool(
            conversation, "suggest_remediation",
            instruction="Now call suggest_remediation to provide a specific code-level fix for this finding.",
        )
        if remediation_record is None:
            remediation_record = {"tool": "suggest_remediation", "arguments": "FALLBACK -- model failed to call this tool",
                                  "result": {"fix_description": "Automated remediation generation failed for this finding. Manual review required.", "code_snippet": "", "reference_links": []}}
            tool_call_log.append(remediation_record)
            conversation = conversation + [{"role": "user", "content": "Now generate a GitHub issue ticket for this finding."}]
        else:
            tool_call_log.append(remediation_record)
            conversation = conversation + [remediation_message, {"role": "tool", "content": json.dumps(remediation_record["result"])}]

        ticket_record, _ = _call_single_tool(
            conversation, "generate_ticket",
            instruction="Now call generate_ticket to draft a GitHub issue for this finding.",
        )
        if ticket_record is None:
            ticket_record = {"tool": "generate_ticket", "arguments": "FALLBACK -- model failed to call this tool",
                             "result": {"title": f"[NEEDS TRIAGE] {finding.title}", "body_markdown": f"Automated ticket generation failed. Finding: {finding.description}", "priority": "P2", "assignee_placeholder": "@security-team"}}
        tool_call_log.append(ticket_record)
        iterations = 3

    return {"finding_id": finding.id, "finding_title": finding.title, "finding_source": finding.source,
            "tool_calls": tool_call_log, "escalated": escalated, "iterations": iterations}


def triage_all(findings, save_incrementally_to=None):
    """Deduplicate findings before any LLM call, then triage each unique finding."""
    original_findings = list(findings)
    unique_findings = deduplicate_findings(original_findings)
    duplicate_count = len(original_findings) - len(unique_findings)
    if duplicate_count:
        print(f"Deduplication removed {duplicate_count} duplicate finding(s).")

    results = []
    for i, finding in enumerate(unique_findings, start=1):
        print(f"[{i}/{len(unique_findings)}] Triaging {finding.id}: {finding.title}...")
        try:
            result = triage_finding(finding)
            status = "ESCALATED" if result["escalated"] else "auto-triaged"
            print(f"  -> {status} in {result['iterations']} iteration(s), {len(result['tool_calls'])} tool call(s)")
        except Exception as e:
            print(f"  -> ERROR: {e}. Escalating this finding and continuing.")
            result = {"finding_id": finding.id, "finding_title": finding.title, "finding_source": finding.source,
                      "tool_calls": [{"tool": "pipeline_error", "arguments": None, "result": {"error": str(e)}}],
                      "escalated": True, "iterations": 0}
        results.append(result)
        if save_incrementally_to:
            directory = os.path.dirname(save_incrementally_to)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(save_incrementally_to, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
    return results
