"""
diagnose_remediation.py

suggest_remediation has more complex arguments than classify_severity
(a free-text code snippet, and an array of URLs). This script forces the
model to call ONLY suggest_remediation and prints the raw response,
so we can see exactly what's going wrong -- e.g. the model refusing to
call it, calling it with malformed arguments, or something else.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ollama_client import chat
from tool_definitions import TOOLS

remediation_tool = next(t for t in TOOLS if t["function"]["name"] == "suggest_remediation")

messages = [
    {
        "role": "system",
        "content": "You are a security assistant. Call the suggest_remediation tool to fix the described issue."
    },
    {
        "role": "user",
        "content": (
            "The following code uses subprocess.call with shell=True and unsanitized input, "
            "a shell injection vulnerability. Call suggest_remediation with a fix."
        )
    }
]

print("Sending request, forced to suggest_remediation only...\n")
response = chat(messages, tools=[remediation_tool])
message = response["message"]

print("Raw message object:")
print(json.dumps(message, indent=2))