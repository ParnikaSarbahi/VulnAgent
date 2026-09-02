"""Command-line entrypoint for the complete VulnAgent pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.agent_core import triage_all
from scanners.bandit_parser import parse_bandit_output
from scanners.scan_loader import collect_findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the VulnAgent security triage pipeline.")
    parser.add_argument("--bandit-report", help="Existing Bandit JSON report to ingest.")
    parser.add_argument("--bandit-target", help="Path to scan with Bandit.")
    parser.add_argument("--trivy-target", help="Filesystem, repository, rootfs, or image target for Trivy.")
    parser.add_argument("--trivy-type", default="fs", choices=["fs", "repo", "rootfs", "image"])
    parser.add_argument("--zap-url", help="HTTP(S) target for OWASP ZAP baseline scanning.")
    parser.add_argument("--scanner-output-dir", default="reports/scans")
    parser.add_argument("--output", default="reports/triage_results.json")
    return parser


def load_findings(args: argparse.Namespace):
    if args.bandit_report and args.bandit_target:
        raise ValueError("Use either --bandit-report or --bandit-target, not both.")
    if args.bandit_report:
        findings = parse_bandit_output(args.bandit_report)
        additional = collect_findings(
            trivy_target=args.trivy_target,
            trivy_target_type=args.trivy_type,
            zap_target_url=args.zap_url,
            output_dir=args.scanner_output_dir,
        )
        return findings + additional

    return collect_findings(
        bandit_target=args.bandit_target,
        trivy_target=args.trivy_target,
        trivy_target_type=args.trivy_type,
        zap_target_url=args.zap_url,
        output_dir=args.scanner_output_dir,
    )


def main() -> int:
    args = build_parser().parse_args()
    findings = load_findings(args)
    if not findings:
        raise SystemExit("No scanner findings were produced. Provide a scanner target or report.")

    print(f"Loaded {len(findings)} normalized finding(s).")
    results = triage_all(findings, save_incrementally_to=args.output)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    escalated = sum(1 for result in results if result.get("escalated"))
    print(f"Completed {len(results)} triage result(s); {escalated} escalated.")
    print(f"Results written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
