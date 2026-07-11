"""
finding_schema.py

Defines ONE common "finding" shape that every scanner parser (Bandit, Trivy,
ZAP) will normalize its output into. This is the schema the rest of
VulnAgent (tools, agent core, eval, reports) will work with — nobody
downstream needs to know or care whether a finding originally came from
Bandit or Trivy.

Using pydantic means: if a parser produces malformed data (wrong type,
missing required field), we get a clear validation error immediately,
instead of a confusing failure three steps later inside the LLM agent loop.
"""

from pydantic import BaseModel
from typing import Optional


class Finding(BaseModel):
    id: str                      # unique id we generate, e.g. "bandit-0001"
    source: str                  # which scanner produced this: "bandit" | "trivy" | "zap"
    title: str                   # short human-readable description
    description: str             # fuller explanation of the issue
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    raw_severity: str            # the scanner's own severity label (varies by tool)
    cwe_id: Optional[int] = None
    reference_url: Optional[str] = None
    code_snippet: Optional[str] = None