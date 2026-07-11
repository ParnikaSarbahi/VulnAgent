"""
agent_core.py

The heart of VulnAgent: takes a list of Findings, and for each one, runs
a multi-turn tool-use conversation with the model until it's done
triaging that finding (or we hit a safety cap on iterations).

THE LOOP, per finding:
  1. Describe the finding to the model, give it all 4 tools.
  2. Model responds -- either with tool_calls, or plain text (done).
  3. For each tool_call: look up the real function in TOOL_DISPATCH,
     execute it with the model's arguments, capture the result.
  4. Append the tool results back into the conversation as "tool" role
     messages, so the model can see what happened and decide what to do
     next (e.g. after classifying HIGH severity, it should then call
     suggest_remediation and generate_ticket).
  5. Repeat from step 2, until the model stops calling tools or we hit
     MAX_ITERATIONS (a safety cap -- without this, a model that gets
     confused could loop forever, calling tools repeatedly).

We collect every tool call+result made during a finding's triage into
one structured record -- that becomes the finding's full triage output.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanners"))

from ollama_client import chat
from tool_definitions import TOOLS
from tool_implementations import TOOL_DISPATCH

MAX_ITERATIONS = 6  # safety cap: max tool-call round-trips per finding

SYSTEM_PROMPT = """You are a security triage agent. You will be asked to call specific
tools one at a time. For each tool call, follow these rules strictly:

- Base every field on the SPECIFIC finding you were given -- its file, code,
  and description. Never write generic placeholders like "None provided" or
  "N/A". If you're not certain, give your best specific assessment anyway.
- cvss_score must be a real number between 0.0 and 10.0 reflecting the
  actual severity of THIS finding (e.g. shell injection / RCE issues score
  high, ~7-9; hardcoded low-impact config issues score lower, ~2-4).
- confidence_level must be LOW, MEDIUM, or HIGH, reflecting your genuine
  certainty about this specific classification. Use HIGH for clear-cut
  cases, LOW only when the finding is genuinely ambiguous.
- business_impact must be a specific 1-2 sentence explanation of what could
  go wrong in THIS case, not a generic statement.

Use these examples to calibrate your severity scale -- especially for
findings where the risk isn't obvious from the code alone:

- CRITICAL example: a hardcoded cloud provider secret key (AWS/GCP/Azure)
  committed to source control. This is immediately exploitable by anyone
  with repo access and can lead to full account takeover -- CRITICAL,
  regardless of how simple the code itself looks.
- CRITICAL example: XML parsing with external entity resolution enabled
  (XXE), which can expose local files or lead to remote code execution --
  CRITICAL even though the vulnerable code is often just one line.
- HIGH example: SQL injection via string-formatted queries, or shell
  injection via shell=True with unsanitized input -- both are classic,
  well-understood, directly exploitable vulnerability classes.
- LOW example: a predictable but non-user-controlled temp file path, or
  a debug flag enabling a hardcoded (non-injectable) shell command --
  real but not directly exploitable by an attacker today.

Severity is about IMPACT IF EXPLOITED, not how complex the vulnerable code
looks. A one-line hardcoded secret or XXE-enabled parser can be far more
dangerous than a longer, more "suspicious-looking" snippet.

Call only the tool you are asked to call in each request."""


def _finding_to_prompt(finding):
    """Formats a Finding object into a plain-language description for the model."""
    return (
        f"Triage this vulnerability finding:\n"
        f"Source: {finding.source}\n"
        f"Title: {finding.title}\n"
        f"Description: {finding.description}\n"
        f"File: {finding.file_path}, line {finding.line_number}\n"
        f"Scanner's own severity label: {finding.raw_severity}\n"
        f"CWE ID: {finding.cwe_id}\n"
        f"Code:\n{finding.code_snippet}"
    )


CONFIDENCE_THRESHOLD = 0.5  # below this, force escalation regardless of severity


def _extract_fallback_tool_call(message, expected_tool_name):
    """
    Some models occasionally emit a tool call as JSON text inside the
    `content` field (e.g. {"name": "suggest_remediation", "parameters": {...}})
    instead of using Ollama's native `tool_calls` field -- we observed this
    happening specifically with complex, multi-line arguments (code snippets
    with escaped quotes/newlines seem to push the model off the structured
    path). Rather than treat this as a hard failure, we try to recover the
    call by parsing the content as JSON.

    Returns the arguments dict if recovery succeeds, else None.
    """
    content = message.get("content", "")
    if not content:
        return None

    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        # Model output was near-valid JSON but not quite -- we observed a
        # specific pattern where an extra stray quote appears right before
        # the final closing brace (e.g. `...]}"}` instead of `...]}}`).
        # Try one targeted repair before giving up entirely.
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
    """
    Sends a chat request restricted to ONE specific tool (instead of all 4).
    This forces the model to call exactly that tool -- it can't wander off
    or skip steps, because nothing else is available to call. We use this
    to enforce deterministic control flow: OUR code decides the sequence
    of steps, the model only decides the content of each step.

    `instruction`, if given, is appended as a fresh user message before the
    call. We found this necessary empirically: once a conversation contains
    prior tool-call/tool-result history, the model sometimes loses track of
    what it's currently being asked to do and reverts to re-explaining its
    previous answer in plain text instead of calling the newly available
    tool. An explicit, direct instruction ("Now call X") fixes this far
    more reliably than expecting the model to infer intent from the
    conversation state and the tool list alone.
    """
    tool_def = next(t for t in TOOLS if t["function"]["name"] == tool_name)

    call_messages = messages
    if instruction:
        call_messages = messages + [{"role": "user", "content": instruction}]

    response = chat(call_messages, tools=[tool_def])
    message = response["message"]
    tool_calls = message.get("tool_calls")

    args = None
    if tool_calls:
        args = tool_calls[0]["function"]["arguments"]
    else:
        # Native tool_calls empty -- try recovering a call the model may
        # have emitted as JSON text in content instead.
        args = _extract_fallback_tool_call(message, tool_name)

    if args is None:
        # Genuinely no tool call, recoverable or otherwise.
        return None, message

    try:
        result = TOOL_DISPATCH[tool_name](**args)
    except TypeError as e:
        result = {"error": f"Bad arguments for {tool_name}: {e}"}

    return {"tool": tool_name, "arguments": args, "result": result}, message


def triage_finding(finding):
    """
    Runs a DETERMINISTIC triage sequence for ONE finding. Unlike a fully
    free-form agent loop, we control the sequence in code:

      1. Always call classify_severity first (forced -- only tool available).
      2. In Python, inspect the result: if severity is CRITICAL or
         confidence is below CONFIDENCE_THRESHOLD -> call escalate_to_human
         (forced) and stop.
      3. Otherwise -> call suggest_remediation (forced), then
         generate_ticket (forced).

    This guarantees every finding gets a consistent, policy-compliant
    triage path even when the underlying model is too small/unreliable to
    plan multi-step tool sequences on its own.
    """
    base_messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": _finding_to_prompt(finding)},
    ]

    tool_call_log = []
    escalated = False

    # Step 1: forced classify_severity
    call_record, model_message = _call_single_tool(base_messages, "classify_severity")
    if call_record is None:
        # Model completely failed to classify -- escalate as a safety fallback,
        # we cannot triage what we can't even get a severity for.
        escalate_record, _ = _call_single_tool(
            base_messages + [{"role": "user", "content": "Escalate this finding: classification failed."}],
            "escalate_to_human",
        )
        if escalate_record:
            tool_call_log.append(escalate_record)
        return {
            "finding_id": finding.id,
            "finding_title": finding.title,
            "finding_source": finding.source,
            "tool_calls": tool_call_log,
            "escalated": True,
            "iterations": 1,
        }

    tool_call_log.append(call_record)
    classification = call_record["result"]

    conversation = base_messages + [
        model_message,
        {"role": "tool", "content": json.dumps(classification)},
    ]

    severity = str(classification.get("severity", "")).upper()
    confidence = classification.get("confidence", 0.0)

    # NOTE on confidence: LLMs (including large hosted ones) are generally
    # unreliable at producing calibrated numeric self-confidence in a single
    # tool call -- it's an introspection task, not a reasoning task. Rather
    # than trust that number alone, we treat CRITICAL severity as the
    # primary, reliable escalation trigger, and treat a reported confidence
    # below the threshold as a secondary signal worth flagging but logging
    # explicitly (see confidence_flag below) rather than silently trusting
    # or silently dropping it.
    low_confidence = confidence < CONFIDENCE_THRESHOLD

    if severity == "CRITICAL" or low_confidence:
        # Step 2a: forced escalation
        escalate_record, _ = _call_single_tool(
            conversation, "escalate_to_human",
            instruction="Now call escalate_to_human to escalate this specific finding, using the classification above as context."
        )
        if escalate_record:
            tool_call_log.append(escalate_record)
            escalated = True
        else:
            # The forced tool call failed -- do NOT silently continue.
            # Log an explicit error record and fall back to a manually
            # constructed escalation using the classification data we
            # already have, so this finding is never lost or misreported.
            fallback_result = TOOL_DISPATCH["escalate_to_human"](
                reason=f"Escalation triggered ({'CRITICAL severity' if severity == 'CRITICAL' else 'low confidence'}), "
                       f"but model failed to generate escalation details",
                context=f"Classification: {json.dumps(classification)}",
                urgency="HIGH" if severity == "CRITICAL" else "MEDIUM",
            )
            tool_call_log.append({
                "tool": "escalate_to_human",
                "arguments": "FALLBACK -- model failed to call this tool",
                "result": fallback_result,
            })
            escalated = True
        iterations = 2
    else:
        # Step 2b: forced remediation, then forced ticket generation
        remediation_record, remediation_message = _call_single_tool(
            conversation, "suggest_remediation",
            instruction="Now call suggest_remediation to provide a specific code-level fix for this finding."
        )
        iterations = 2

        if remediation_record is None:
            # Forced call failed -- log it explicitly instead of silently
            # skipping, and build a minimal fallback so this finding still
            # has SOME remediation guidance rather than nothing.
            remediation_record = {
                "tool": "suggest_remediation",
                "arguments": "FALLBACK -- model failed to call this tool",
                "result": {
                    "fix_description": "Automated remediation generation failed for this finding. Manual review required.",
                    "code_snippet": "",
                    "reference_links": [],
                },
            }
            tool_call_log.append(remediation_record)
            conversation = conversation + [
                {"role": "user", "content": "Now generate a GitHub issue ticket for this finding."}
            ]
        else:
            tool_call_log.append(remediation_record)
            conversation = conversation + [
                remediation_message,
                {"role": "tool", "content": json.dumps(remediation_record["result"])},
            ]
        iterations = 3

        ticket_record, _ = _call_single_tool(
            conversation, "generate_ticket",
            instruction="Now call generate_ticket to draft a GitHub issue for this finding."
        )

        if ticket_record is None:
            ticket_record = {
                "tool": "generate_ticket",
                "arguments": "FALLBACK -- model failed to call this tool",
                "result": {
                    "title": f"[NEEDS TRIAGE] {finding.title}",
                    "body_markdown": f"Automated ticket generation failed. Finding: {finding.description}",
                    "priority": "P2",
                    "assignee_placeholder": "@security-team",
                },
            }
        tool_call_log.append(ticket_record)

    return {
        "finding_id": finding.id,
        "finding_title": finding.title,
        "finding_source": finding.source,
        "tool_calls": tool_call_log,
        "escalated": escalated,
        "iterations": iterations,
    }


def triage_all(findings, save_incrementally_to=None):
    """
    Runs triage_finding() over a list of Findings, printing progress as it
    goes. Wraps each finding in a try/except so a transient failure (e.g. a
    slow/timed-out request to Ollama) on ONE finding doesn't lose progress
    on all the others -- a failed finding gets logged as a clear error
    record and escalated, and the batch continues.

    If save_incrementally_to is given a file path, results are written to
    disk after EVERY finding (not just at the end), so a crash mid-batch
    never loses already-completed work.
    """
    results = []
    for i, finding in enumerate(findings, start=1):
        print(f"[{i}/{len(findings)}] Triaging {finding.id}: {finding.title}...")
        try:
            result = triage_finding(finding)
            status = "ESCALATED" if result["escalated"] else "auto-triaged"
            print(f"  -> {status} in {result['iterations']} iteration(s), "
                  f"{len(result['tool_calls'])} tool call(s)")
        except Exception as e:
            # Don't let one bad finding (e.g. a network timeout) kill the
            # whole batch. Log it clearly and escalate as a safety fallback.
            print(f"  -> ERROR: {e}. Escalating this finding and continuing.")
            result = {
                "finding_id": finding.id,
                "finding_title": finding.title,
                "finding_source": finding.source,
                "tool_calls": [{
                    "tool": "pipeline_error",
                    "arguments": None,
                    "result": {"error": str(e)},
                }],
                "escalated": True,
                "iterations": 0,
            }

        results.append(result)

        if save_incrementally_to:
            os.makedirs(os.path.dirname(save_incrementally_to), exist_ok=True)
            with open(save_incrementally_to, "w") as f:
                json.dump(results, f, indent=2)

    return results


if __name__ == "__main__":
    # Run the full batch: python agent/agent_core.py
    from bandit_parser import parse_bandit_output

    findings = parse_bandit_output(
        os.path.join(os.path.dirname(__file__), "..", "samples", "bandit_raw_output.json")
    )

    print(f"Running full triage on {len(findings)} findings. This may take a while on CPU...\n")

    output_path = os.path.join(os.path.dirname(__file__), "..", "reports", "triage_results.json")
    results = triage_all(findings, save_incrementally_to=output_path)

    escalated_count = sum(1 for r in results if r["escalated"])
    print(f"\nDone. {len(results)} findings triaged, {escalated_count} escalated to human.")
    print(f"Saved to {output_path}")