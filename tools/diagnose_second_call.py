"""
diagnose_second_call.py

diagnose_remediation.py tests suggest_remediation in ISOLATION (one clean
user message) and it works fine. But in the real pipeline, suggest_remediation
is called as the SECOND forced tool call, after a full classify_severity
exchange (including the model's own prior tool-call message) has already
been appended to the conversation. This script reproduces that exact
multi-turn context to see if that's what breaks the second call.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ollama_client import chat
from tool_definitions import TOOLS

classify_tool = next(t for t in TOOLS if t["function"]["name"] == "classify_severity")
remediation_tool = next(t for t in TOOLS if t["function"]["name"] == "suggest_remediation")

# Step 1: same as the real pipeline -- forced classify_severity call
base_messages = [
    {"role": "system", "content": "You are a security triage agent. Call the requested tool with specific, non-generic values."},
    {"role": "user", "content": (
        "Triage this vulnerability finding:\n"
        "Source: bandit\nTitle: [B602] subprocess call with shell=True\n"
        "Description: subprocess call with shell=True identified, security issue.\n"
        "File: samples/vulnerable_app.py, line 17\nScanner severity: HIGH\nCWE ID: 78\n"
        "Code: subprocess.call(user_input, shell=True)"
    )},
]

print("STEP 1: classify_severity (forced)")
response1 = chat(base_messages, tools=[classify_tool])
message1 = response1["message"]
print("Raw message 1:")
print(json.dumps(message1, indent=2))

if not message1.get("tool_calls"):
    print("\nStep 1 itself failed to produce a tool call -- stopping here.")
    sys.exit(0)

classification_result = {"severity": "HIGH", "cvss_score": 7.5, "business_impact": "test", "confidence": 0.9}

# Step 2: append the model's own message + a tool result, exactly like triage_finding does
conversation = base_messages + [
    message1,
    {"role": "tool", "content": json.dumps(classification_result)},
]

print("\n\nSTEP 2: suggest_remediation (forced, with prior context)")
response2 = chat(conversation, tools=[remediation_tool])
message2 = response2["message"]
print("Raw message 2:")
print(json.dumps(message2, indent=2))