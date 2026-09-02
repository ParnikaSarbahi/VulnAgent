"""
Finding deduplication utilities.

Scanners can report the same underlying vulnerability more than once. This
module creates a stable fingerprint from normalized vulnerability evidence and
removes duplicate findings before they reach the LLM triage pipeline.

The first implementation deliberately uses deterministic, explainable rules
rather than embeddings or an LLM. This keeps deduplication cheap and
repeatable while leaving room for richer correlation later.
"""

import hashlib
import re
from typing import Iterable

from .finding_schema import Finding


def _normalize(value: str | None) -> str:
    """Normalize free text so harmless formatting differences do not matter."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.strip().lower())


def fingerprint_finding(finding: Finding) -> str:
    """Return a stable SHA-256 fingerprint for a finding.

    Priority:
    1. CWE + file + line when location evidence exists.
    2. CWE + file + normalized title when only file evidence exists.
    3. CWE + normalized title + normalized description otherwise.

    Scanner *source* and scanner-generated IDs are intentionally excluded so
    equivalent findings from Bandit, Trivy, and ZAP can eventually correlate.
    """
    cwe = str(finding.cwe_id or "")
    file_path = _normalize(finding.file_path)
    title = _normalize(finding.title)
    description = _normalize(finding.description)

    if cwe and file_path and finding.line_number is not None:
        material = f"cwe={cwe}|file={file_path}|line={finding.line_number}"
    elif cwe and file_path:
        material = f"cwe={cwe}|file={file_path}|title={title}"
    else:
        material = f"cwe={cwe}|title={title}|description={description}"

    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Return findings with deterministic duplicates removed.

    The first occurrence wins, preserving scanner/parser ordering. This makes
    the result deterministic and avoids silently changing the Finding schema.
    """
    unique: list[Finding] = []
    seen: set[str] = set()

    for finding in findings:
        fingerprint = fingerprint_finding(finding)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(finding)

    return unique
