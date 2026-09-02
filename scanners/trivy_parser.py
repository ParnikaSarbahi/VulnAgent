"""Normalize Trivy vulnerability JSON into VulnAgent Findings."""

import json
from .finding_schema import Finding


def _severity(value: str | None) -> str:
    return (value or "UNKNOWN").upper()


def parse_trivy_output(json_path: str) -> list[Finding]:
    """Parse Trivy JSON output from `trivy image --format json ...`."""
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    findings: list[Finding] = []
    counter = 1
    for target in raw.get("Results", []):
        target_name = target.get("Target", "unknown-target")
        for vulnerability in target.get("Vulnerabilities") or []:
            vuln_id = vulnerability.get("VulnerabilityID", "UNKNOWN")
            pkg = vulnerability.get("PkgName", "unknown-package")
            installed = vulnerability.get("InstalledVersion", "unknown")
            fixed = vulnerability.get("FixedVersion")
            title = f"[{vuln_id}] {pkg} {installed}"
            description = vulnerability.get("Description") or (
                f"Trivy detected {vuln_id} in package {pkg} ({installed}) in {target_name}."
            )
            if fixed:
                description += f" A fixed version is available: {fixed}."

            references = vulnerability.get("References") or []
            reference_url = references[0] if references else vulnerability.get("PrimaryURL")
            cwe_ids = vulnerability.get("CweIDs") or []
            cwe_id = None
            if cwe_ids:
                try:
                    cwe_id = int(str(cwe_ids[0]).split("-")[-1])
                except ValueError:
                    pass

            findings.append(Finding(
                id=f"trivy-{counter:04d}", source="trivy", title=title,
                description=description, file_path=target_name, line_number=None,
                raw_severity=_severity(vulnerability.get("Severity")), cwe_id=cwe_id,
                reference_url=reference_url, code_snippet=None,
            ))
            counter += 1
    return findings
