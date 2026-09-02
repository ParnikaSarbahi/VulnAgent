"""Normalize OWASP ZAP JSON alerts into VulnAgent Findings."""

import json
import re
from scanners.finding_schema import Finding


def _severity_from_risk(risk: str | None) -> str:
    value = (risk or "UNKNOWN").strip().upper()
    return {
        "3": "HIGH",
        "2": "MEDIUM",
        "1": "LOW",
        "0": "INFO",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFORMATIONAL": "INFO",
        "INFO": "INFO",
    }.get(value, "UNKNOWN")


def _extract_cwe(alert: dict) -> int | None:
    for key in ("cweid", "cweId", "CWEID"):
        value = alert.get(key)
        if value in (None, "", "0"):
            continue
        match = re.search(r"(\d+)", str(value))
        if match:
            return int(match.group(1))
    return None


def _alerts_from_site(site: dict) -> list[dict]:
    """Support both common ZAP report nesting shapes."""
    alerts = []
    for alert in site.get("alerts") or []:
        alerts.append(alert)
    return alerts


def parse_zap_output(json_path: str) -> list[Finding]:
    """Parse a ZAP JSON report and normalize its alerts."""
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    findings: list[Finding] = []
    counter = 1

    # ZAP's JSON export commonly stores alerts under site[].alerts[].
    sites = raw.get("site") or raw.get("sites") or []
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_name = site.get("@name") or site.get("name") or site.get("host") or "unknown-site"
        for alert in _alerts_from_site(site):
            alert_name = alert.get("name") or alert.get("alert") or "Unknown ZAP alert"
            description = alert.get("desc") or alert.get("description") or ""
            solution = alert.get("solution") or ""
            instances = alert.get("instances") or alert.get("instance") or []
            if isinstance(instances, dict):
                instances = [instances]

            # Preserve one normalized finding per alert instance when ZAP
            # provides concrete URLs/locations; otherwise preserve the alert.
            instance_items = instances or [{}]
            for instance in instance_items:
                url = instance.get("uri") or instance.get("url") or site_name
                param = instance.get("param") or instance.get("parameter")
                location = f"{url} (parameter: {param})" if param else str(url)
                detail = description
                if solution:
                    detail += f" Remediation suggested by ZAP: {solution}"

                findings.append(Finding(
                    id=f"zap-{counter:04d}",
                    source="zap",
                    title=alert_name,
                    description=detail,
                    file_path=location,
                    line_number=None,
                    raw_severity=_severity_from_risk(
                        alert.get("riskdesc") or alert.get("risk") or alert.get("riskcode")
                    ),
                    cwe_id=_extract_cwe(alert),
                    reference_url=alert.get("reference") or alert.get("solutionUrl"),
                    code_snippet=None,
                ))
                counter += 1

    return findings
