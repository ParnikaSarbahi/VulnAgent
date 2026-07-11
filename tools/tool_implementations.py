"""
tool_implementations.py

The actual Python logic that runs when the model calls each tool. Note
the division of labor: the MODEL decides the severity rating, the fix,
the ticket text, etc. (that's the "AI reasoning" part) — these functions
just take that decision, validate/structure it, and (for some tools)
persist it to disk. This mirrors how real agent tools work: the tool
isn't "smart," it's a reliable executor for what the model decided.

Each function's signature matches the "parameters" schema for that tool
in tool_definitions.py — the agent loop (Step 4) will call these with
**kwargs unpacked from the model's tool_call arguments.
"""

import json
import os
from datetime import datetime, timezone

ESCALATIONS_LOG = os.path.join(os.path.dirname(__file__), "..", "reports", "escalations_log.jsonl")


def _coerce_float(value, default=0.0):
    """
    Local LLMs (unlike hosted APIs like Claude/GPT) don't always respect
    JSON types strictly -- numeric fields sometimes come back as strings
    (e.g. "8.5" instead of 8.5), or occasionally missing entirely. This
    helper safely converts whatever we get into a float, falling back to
    a default instead of crashing the whole pipeline over one bad field.
    """
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


CONFIDENCE_LEVEL_MAP = {
    "LOW": 0.25,
    "MEDIUM": 0.6,
    "HIGH": 0.9,
}


def classify_severity(severity, cvss_score, business_impact, confidence_level):
    """
    Validates and returns the model's severity classification.

    NOTE: confidence is elicited from the model as a categorical LOW/MEDIUM/HIGH
    label rather than a raw 0.0-1.0 float. Small (and even large) LLMs are much
    more reliable at picking from a small set of labels than producing calibrated
    continuous numbers -- we saw this empirically (confidence as a float defaulted
    to 0 in ~70% of real triage runs, regardless of actual certainty). We map the
    label to a numeric value here so the rest of the pipeline (escalation
    thresholds, eval scoring) can still work with a single confidence number.
    """
    confidence_level = str(confidence_level).upper()
    numeric_confidence = CONFIDENCE_LEVEL_MAP.get(confidence_level, 0.5)  # unknown label -> neutral default

    result = {
        "severity": severity,
        "cvss_score": _coerce_float(cvss_score),
        "business_impact": business_impact,
        "confidence_level": confidence_level,
        "confidence": numeric_confidence,
    }
    return result


def suggest_remediation(fix_description, code_snippet, reference_links):
    """
    Validates and returns the model's suggested remediation.

    NOTE: reference_links is elicited from the model as a comma-separated
    STRING, not a JSON array. We found empirically that array-typed tool
    parameters caused this specific tool to fail 100% of the time (10/10)
    with our local model, while every other tool (which only uses
    strings/numbers/enums) succeeded reliably. Array/list types appear to
    be much harder for constrained JSON generation on smaller/quantized
    models. We parse the string back into a clean list here so the rest
    of the pipeline still gets a proper list.
    """
    if isinstance(reference_links, str):
        links_list = [link.strip() for link in reference_links.split(",") if link.strip()]
    elif isinstance(reference_links, list):
        links_list = reference_links  # in case a future/different model does return an array
    else:
        links_list = []

    result = {
        "fix_description": fix_description,
        "code_snippet": code_snippet,
        "reference_links": links_list,
    }
    return result


def generate_ticket(title, body_markdown, priority, assignee_placeholder):
    """Validates and returns a structured GitHub issue draft."""
    result = {
        "title": title,
        "body_markdown": body_markdown,
        "priority": priority,
        "assignee_placeholder": assignee_placeholder,
    }
    return result


def escalate_to_human(reason, context, urgency):
    """
    Validates the escalation and APPENDS it to a persistent log file
    (reports/escalations_log.jsonl). Unlike the other 3 tools, this one
    has a side effect — escalations need to survive beyond a single run
    so a human can review them later. We use JSONL (one JSON object per
    line) so the log can be appended to safely without re-parsing the
    whole file each time.
    """
    result = {
        "reason": reason,
        "context": context,
        "urgency": urgency,
        "escalated_at": datetime.now(timezone.utc).isoformat(),
    }

    os.makedirs(os.path.dirname(ESCALATIONS_LOG), exist_ok=True)
    with open(ESCALATIONS_LOG, "a") as f:
        f.write(json.dumps(result) + "\n")

    return result


# Maps tool name (as the model will refer to it) -> the actual function.
# The agent loop (Step 4) will use this to dispatch tool calls dynamically
# instead of a long if/elif chain.
TOOL_DISPATCH = {
    "classify_severity": classify_severity,
    "suggest_remediation": suggest_remediation,
    "generate_ticket": generate_ticket,
    "escalate_to_human": escalate_to_human,
}