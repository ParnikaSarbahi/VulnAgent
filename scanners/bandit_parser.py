"""
bandit_parser.py

Reads Bandit's raw JSON output (produced via `bandit -f json -o out.json`)
and converts each result into our common Finding schema (see
finding_schema.py). This isolates "Bandit's weird field names" in one
place, so the rest of the codebase never has to know what a
`issue_cwe.id` or `test_id` is.
"""

import json
from finding_schema import Finding


def parse_bandit_output(json_path: str) -> list[Finding]:
    """
    Args:
        json_path: path to a JSON file produced by
                   `bandit -f json -o <json_path> <target>`

    Returns:
        A list of normalized Finding objects.
    """
    with open(json_path, "r") as f:
        raw = json.load(f)

    findings = []

    for i, result in enumerate(raw.get("results", []), start=1):
        # Bandit's test_name is sometimes generic (e.g. "blacklist" for
        # several different rule types), so we build a more descriptive
        # title from the test_id and a truncated version of the issue text.
        test_id = result.get("test_id", "")
        issue_text = result.get("issue_text", "")
        short_desc = issue_text[:70] + ("..." if len(issue_text) > 70 else "")
        descriptive_title = f"[{test_id}] {short_desc}" if test_id else issue_text

        finding = Finding(
            id=f"bandit-{i:04d}",
            source="bandit",
            title=descriptive_title,
            description=result.get("issue_text", ""),
            file_path=result.get("filename"),
            line_number=result.get("line_number"),
            raw_severity=result.get("issue_severity", "UNKNOWN"),
            cwe_id=result.get("issue_cwe", {}).get("id") if result.get("issue_cwe") else None,
            reference_url=result.get("more_info"),
            code_snippet=result.get("code"),
        )
        findings.append(finding)

    return findings


if __name__ == "__main__":
    # Quick manual test: python scanners/bandit_parser.py
    findings = parse_bandit_output("../samples/bandit_raw_output.json")

    print(f"Parsed {len(findings)} findings from Bandit output.\n")

    for f in findings:
        print(f"[{f.id}] {f.title} (severity={f.raw_severity}, line={f.line_number})")
        print(f"  {f.description}")
        print()

    print("--- First finding, full structure ---")
    print(findings[0].model_dump_json(indent=2))