"""Normalize OWASP ZAP JSON alerts into VulnAgent Findings."""

import json
import re
from .finding_schema import Finding


def _severity_from_risk(risk: str | None) -> str:
    value = (risk or "UNKNOWN").strip().upper()
    # ZAP risk codes: 0 informational, 1 low, 2 medium, 3 high.
    if value.startswith("HIGH") or value == "3":
        return "HIGH"
    if value.startswith("MEDIUM") or value == "2":
        return "MEDIUM"
    if value.startswith("LOW") or value == "1":
        return "LOW"
    if value.startswith("INFORMATIONAL") or value == "INFO" or value == "0":
        return "INFO"
    return "UNKNOWN"


def _extract_cwe(alert: dict) -> int | None:
    for key in ("cweid", "cweId", "CWEID"):
        value = alert.get(key)
        if value in (None, "", "0"):
            continue
        match = re.search(r"(\d+)", str(value))
        if match:
            return int(match.group(1))
    return None


def parse_zap_output(json_path: str) -> list[Finding]:
    """Parse a ZAP JSON report, producing one Finding per alert instance."""
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    findings: list[Finding] = []
    counter = 1
    sites = raw.get("site") or raw.get("sites") or []
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_name = site.get("@name") or site.get("name") or site.get("host") or "unknown-site"
        for alert in site.get("alerts") or []:
            alert_name = alert.get("name") or alert.get("alert") or "Unknown ZAP alert"
            description = alert.get("desc") or alert.get("description") or ""
            solution = alert.get("solution") or ""
            instances = alert.get("instances") or alert.get("instance") or []
            if isinstance(instances, dict):
                instances = [instances]
            for instance in instances or [{}]:
                url = instance.get("uri") or instance.get("url") or site_name
                param = instance.get("param") or instance.get("parameter")
                location = f"{url} (parameter: {param})" if param else str(url)
                detail = description
                if solution:
                    detail += f" Remediation suggested by ZAP: {solution}"
                findings.append(Finding(
                    id=f"zap-{counter:04d}", source="zap", title=alert_name,
                    description=detail, file_path=location, line_number=None,
                    raw_severity=_severity_from_risk(
                        alert.get("riskdesc") or alert.get("risk") or alert.get("riskcode")
                    ), cwe_id=_extract_cwe(alert),
                    reference_url=alert.get("reference") or alert.get("solutionUrl"),
                    code_snippet=None,
                ))
                counter += 1
    return findings
