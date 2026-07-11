"""
check_bandit_severity.py

Reads a Bandit JSON report and enforces our CI pass/fail policy: fail the
build (non-zero exit) if any HIGH-severity finding is present. LOW and
MEDIUM findings are reported but don't block the build -- this mirrors a
realistic policy where teams don't want CI blocked on every minor finding,
but DO want a hard stop on serious, directly exploitable issues.

Usage: python check_bandit_severity.py <path-to-bandit-report.json>
Exit code: 0 if no HIGH-severity findings, 1 if any HIGH-severity findings
(or if the report file itself is missing/malformed -- fail closed, not open).
"""

import sys
import json
from collections import Counter

FAIL_ON_SEVERITIES = {"HIGH"}


def main():
    if len(sys.argv) != 2:
        print("Usage: python check_bandit_severity.py <bandit-report.json>")
        sys.exit(1)

    report_path = sys.argv[1]

    try:
        with open(report_path, "r") as f:
            report = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        # Fail closed: if we can't even read the report, treat that as a
        # build failure rather than silently passing.
        print(f"ERROR: could not read/parse {report_path}: {e}")
        sys.exit(1)

    results = report.get("results", [])
    severity_counts = Counter(r.get("issue_severity", "UNKNOWN").upper() for r in results)

    print("Bandit scan summary:")
    for sev in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if severity_counts.get(sev):
            print(f"  {sev}: {severity_counts[sev]}")

    high_severity_findings = [r for r in results if r.get("issue_severity", "").upper() in FAIL_ON_SEVERITIES]

    if high_severity_findings:
        print(f"\nFAILING BUILD: {len(high_severity_findings)} HIGH-severity finding(s) detected:")
        for finding in high_severity_findings:
            test_id = finding.get("test_id", "?")
            filename = finding.get("filename", "?")
            line = finding.get("line_number", "?")
            issue = finding.get("issue_text", "")
            print(f"  [{test_id}] {filename}:{line} -- {issue}")
        sys.exit(1)

    print("\nNo HIGH-severity findings. Build passes.")
    sys.exit(0)


if __name__ == "__main__":
    main()