"""
test_tools_with_model.py

The real test: send an actual Bandit finding to the model along with our
4 tool definitions, and see whether it correctly chooses to call
classify_severity with sensible arguments. This confirms Ollama's
tool-calling actually works with our model and schema -- not just that
our Python functions work in isolation (test_tools_hardcoded.py already
proved that).

How this works:
1. We send a chat message describing one finding, plus the `tools` list.
2. The model responds with a `tool_calls` field instead of (or alongside)
   plain text, containing the tool name + arguments it wants to call.
3. We don't execute anything automatically here -- we just print what
   the model decided, so you can sanity-check its reasoning before we
   wire up full execution + feeding results back (that's Step 4).
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
sys.path.insert(0, os.path.dirname(__file__))

from ollama_client import chat
from tool_definitions import TOOLS

# One real finding from our Bandit scan, described in plain language
finding_description = """
Finding source: Bandit (SAST)
File: samples/vulnerable_app.py, line 17
Issue: subprocess.call() is used with shell=True and unsanitized user input,
which is a classic shell injection vulnerability (CWE-78).
Code: subprocess.call(user_input, shell=True)
"""

messages = [
    {
        "role": "system",
        "content": (
            "You are a security triage assistant. When given a vulnerability "
            "finding, call the classify_severity tool to assess it. Always "
            "use the tool -- do not just describe the severity in plain text. "
            "You MUST fill in every argument the tool requires, including "
            "numeric ones. For cvss_score, estimate a realistic CVSS v3 base "
            "score between 0.0 and 10.0 based on the finding's severity and "
            "exploitability -- never leave it null or omit it. For confidence, "
            "give your own self-rated confidence in this classification as a "
            "number between 0.0 and 1.0 -- never leave it null or omit it."
        )
    },
    {
        "role": "user",
        "content": f"Please classify the severity of this finding:\n{finding_description}"
    }
]

print("Sending finding to model with tool definitions...\n")
response = chat(messages, tools=TOOLS)

message = response["message"]

if "tool_calls" in message and message["tool_calls"]:
    print(f"Model made {len(message['tool_calls'])} tool call(s):\n")
    for call in message["tool_calls"]:
        print(f"Tool: {call['function']['name']}")
        print(f"Arguments: {json.dumps(call['function']['arguments'], indent=2)}")
else:
    print("Model did NOT make a tool call. Raw response:")
    print(message.get("content", "(empty)"))