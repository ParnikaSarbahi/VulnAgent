"""Unified scanner ingestion for VulnAgent."""

from scanners.deduplicator import deduplicate_findings
from scanners.scanner_runner import run_scanners
from scanners.finding_schema import Finding


def collect_findings(
    *,
    bandit_target: str | None = None,
    trivy_target: str | None = None,
    trivy_target_type: str = "fs",
    zap_target_url: str | None = None,
    output_dir: str = "reports/scans",
) -> list[Finding]:
    """Run requested scanners, normalize results, then remove duplicates."""
    findings = run_scanners(
        bandit_target=bandit_target,
        trivy_target=trivy_target,
        trivy_target_type=trivy_target_type,
        zap_target_url=zap_target_url,
        output_dir=output_dir,
    )
    return deduplicate_findings(findings)
