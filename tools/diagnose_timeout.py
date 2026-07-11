"""
diagnose_timeout.py

Isolates whether the timeout issue is caused by tool-calling specifically,
or by inference being broken/stalled in general. Runs two tests back to
back, each with a wall-clock timer printed, so we can see exactly where
time is being spent.
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
from ollama_client import chat
from tool_definitions import TOOLS

print("TEST 1: Plain chat, no tools")
start = time.time()
try:
    response = chat([{"role": "user", "content": "Say hello in one short sentence."}])
    elapsed = time.time() - start
    print(f"SUCCESS in {elapsed:.1f}s")
    print(response["message"]["content"])
except Exception as e:
    elapsed = time.time() - start
    print(f"FAILED after {elapsed:.1f}s: {e}")

print()
print("TEST 2: Chat WITH tools (minimal message)")
start = time.time()
try:
    response = chat(
        [{"role": "user", "content": "Classify this as HIGH severity: SQL injection in login form."}],
        tools=TOOLS
    )
    elapsed = time.time() - start
    print(f"SUCCESS in {elapsed:.1f}s")
    print(response["message"])
except Exception as e:
    elapsed = time.time() - start
    print(f"FAILED after {elapsed:.1f}s: {e}")