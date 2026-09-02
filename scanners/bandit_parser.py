"""
bandit_parser.py

Reads Bandit's raw JSON output and converts each result into the common
Finding schema. The parser keeps scanner-specific field names isolated from
the rest of VulnAgent.
"""

import json
from .finding_schema import Finding


def parse_bandit_output(json_path: str) -> list[Finding]:
    """Parse a JSON report produced by Bandit."""
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    findings = []
    for i, result in enumerate(raw.get("results", []), start=1):
        test_id = result.get("test_id", "")
        issue_text = result.get("issue_text", "")
        short_desc = issue_text[:70] + ("..." if len(issue_text) > 70 else "")
        descriptive_title = f"[{test_id}] {short_desc}" if test_id else issue_text

        findings.append(Finding(
            id=f"bandit-{i:04d}",
            source="bandit",
            title=descriptive_title,
            description=issue_text,
            file_path=result.get("filename"),
            line_number=result.get("line_number"),
            raw_severity=result.get("issue_severity", "UNKNOWN"),
            cwe_id=result.get("issue_cwe", {}).get("id") if result.get("issue_cwe") else None,
            reference_url=result.get("more_info"),
            code_snippet=result.get("code"),
        ))

    return findings


if __name__ == "__main__":
    findings = parse_bandit_output("../samples/bandit_raw_output.json")
    print(f"Parsed {len(findings)} findings from Bandit output.\n")
    for finding in findings:
        print(f"[{finding.id}] {finding.title} (severity={finding.raw_severity}, line={finding.line_number})")
