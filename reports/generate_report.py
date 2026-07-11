"""
generate_report.py

Reads reports/triage_results.json (produced by agent/agent_core.py) and
produces three stakeholder-facing outputs:

  1. reports/severity_chart.png   -- matplotlib bar chart of severity distribution
  2. reports/stakeholder_report.md -- plain-English summary for non-technical readers
  3. reports/stakeholder_report.json -- structured summary for dashboards/automation

Design note: this reads the SAME triage_results.json that agent_core.py
already produces -- no new agent logic here, purely a presentation layer
over data we've already generated and can trust.
"""

import sys
import os
import json
import html
from collections import Counter
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")  # no display needed, just save to file
import matplotlib.pyplot as plt

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
TRIAGE_RESULTS_PATH = os.path.join(REPORTS_DIR, "triage_results.json")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_COLORS = {
    "CRITICAL": "#8B0000",
    "HIGH": "#E63946",
    "MEDIUM": "#F4A261",
    "LOW": "#2A9D8F",
    "UNKNOWN": "#999999",
}


def _clean_text(text):
    """
    Defensive cleanup for text fields the model generates. We've observed
    the model occasionally producing stray HTML-entity escaping (e.g.
    \\&quot; instead of a plain quote) inside code snippets and descriptions
    -- likely an artifact of how it handles nested quoting when generating
    JSON arguments. Rather than let that leak into the final stakeholder
    report, we unescape HTML entities and strip stray backslash-escapes
    here, once, in one place.
    """
    if not isinstance(text, str):
        return text
    text = html.unescape(text)
    text = text.replace('\\"', '"').replace("\\'", "'")
    return text


def _get_classification(result):
    """Pulls the classify_severity result out of one finding's tool_calls, if present."""
    for call in result["tool_calls"]:
        if call["tool"] == "classify_severity":
            return call["result"]
    return None


def _get_remediation(result):
    for call in result["tool_calls"]:
        if call["tool"] == "suggest_remediation":
            return call["result"]
    return None


def _get_ticket(result):
    for call in result["tool_calls"]:
        if call["tool"] == "generate_ticket":
            return call["result"]
    return None


def _get_escalation(result):
    for call in result["tool_calls"]:
        if call["tool"] == "escalate_to_human":
            return call["result"]
    return None


def build_summary(results):
    """Computes the aggregate stats used across all three report outputs."""
    severity_counts = Counter()
    for r in results:
        classification = _get_classification(r)
        severity = classification["severity"].upper() if classification else "UNKNOWN"
        severity_counts[severity] += 1

    escalated = [r for r in results if r["escalated"]]
    auto_triaged = [r for r in results if not r["escalated"]]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(results),
        "auto_triaged_count": len(auto_triaged),
        "escalated_count": len(escalated),
        "severity_distribution": dict(severity_counts),
    }


def generate_chart(summary, output_path):
    """Bar chart of severity distribution, ordered CRITICAL -> UNKNOWN."""
    counts = summary["severity_distribution"]
    labels = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    values = [counts[s] for s in labels]
    colors = [SEVERITY_COLORS[s] for s in labels]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    bars = ax.bar(labels, values, color=colors)
    ax.set_title("VulnAgent -- Finding Severity Distribution", fontsize=13, fontweight="bold")
    ax.set_ylabel("Number of findings")
    ax.set_ylim(0, max(values) + 1)

    for bar, value in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                 str(value), ha="center", va="bottom", fontweight="bold")

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)


def generate_markdown_report(results, summary, chart_filename, output_path):
    lines = []
    lines.append("# VulnAgent Triage Report\n")
    lines.append(f"*Generated: {summary['generated_at']}*\n")

    lines.append("## Executive Summary\n")
    lines.append(
        f"VulnAgent triaged **{summary['total_findings']} findings**: "
        f"**{summary['auto_triaged_count']}** were auto-triaged (classified, remediated, "
        f"and drafted as tickets without human involvement), and "
        f"**{summary['escalated_count']}** were escalated to a human reviewer "
        f"(critical severity and/or low model confidence).\n"
    )

    lines.append("## Severity Distribution\n")
    lines.append(f"![Severity distribution]({chart_filename})\n")
    for sev in SEVERITY_ORDER:
        count = summary["severity_distribution"].get(sev, 0)
        if count:
            lines.append(f"- **{sev}**: {count}")
    lines.append("")

    lines.append("## Escalated Findings (Human Review Required)\n")
    escalated = [r for r in results if r["escalated"]]
    if not escalated:
        lines.append("_None -- all findings were auto-triaged._\n")
    else:
        for r in escalated:
            classification = _get_classification(r) or {}
            escalation = _get_escalation(r) or {}
            lines.append(f"### {r['finding_title']}")
            lines.append(f"- **Finding ID**: {r['finding_id']}  ")
            lines.append(f"- **Severity**: {classification.get('severity', 'UNKNOWN')}  ")
            lines.append(f"- **Reason for escalation**: {escalation.get('reason', 'n/a')}  ")
            lines.append(f"- **Urgency**: {escalation.get('urgency', 'n/a')}  ")
            lines.append(f"- **Context for reviewer**: {escalation.get('context', 'n/a')}\n")

    lines.append("## Auto-Triaged Findings\n")
    auto = [r for r in results if not r["escalated"]]
    if not auto:
        lines.append("_None -- all findings were escalated._\n")
    else:
        for r in auto:
            classification = _get_classification(r) or {}
            remediation = _get_remediation(r) or {}
            ticket = _get_ticket(r) or {}
            lines.append(f"### {r['finding_title']}")
            lines.append(f"- **Finding ID**: {r['finding_id']}  ")
            lines.append(f"- **Severity**: {classification.get('severity', 'UNKNOWN')} "
                          f"(CVSS {classification.get('cvss_score', 'n/a')})  ")
            lines.append(f"- **Business impact**: {classification.get('business_impact', 'n/a')}  ")
            lines.append(f"- **Recommended fix**: {_clean_text(remediation.get('fix_description', 'n/a'))}  ")
            if remediation.get("code_snippet"):
                lines.append(f"  ```python\n  {_clean_text(remediation['code_snippet'])}\n  ```")
            lines.append(f"- **Suggested ticket priority**: {ticket.get('priority', 'n/a')}\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def generate_json_report(results, summary, output_path):
    findings_out = []
    for r in results:
        classification = _get_classification(r) or {}
        remediation = _get_remediation(r)
        ticket = _get_ticket(r)
        escalation = _get_escalation(r)

        findings_out.append({
            "finding_id": r["finding_id"],
            "title": r["finding_title"],
            "source": r["finding_source"],
            "severity": classification.get("severity"),
            "cvss_score": classification.get("cvss_score"),
            "business_impact": classification.get("business_impact"),
            "confidence_level": classification.get("confidence_level"),
            "escalated": r["escalated"],
            "remediation": remediation,
            "ticket": ticket,
            "escalation": escalation,
        })

    output = {"summary": summary, "findings": findings_out}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


def generate_all_reports():
    if not os.path.exists(TRIAGE_RESULTS_PATH):
        print(f"ERROR: {TRIAGE_RESULTS_PATH} not found. Run agent/agent_core.py first.")
        sys.exit(1)

    with open(TRIAGE_RESULTS_PATH, "r") as f:
        results = json.load(f)

    summary = build_summary(results)

    chart_path = os.path.join(REPORTS_DIR, "severity_chart.png")
    generate_chart(summary, chart_path)
    print(f"Chart saved to {chart_path}")

    md_path = os.path.join(REPORTS_DIR, "stakeholder_report.md")
    generate_markdown_report(results, summary, "severity_chart.png", md_path)
    print(f"Markdown report saved to {md_path}")

    json_path = os.path.join(REPORTS_DIR, "stakeholder_report.json")
    generate_json_report(results, summary, json_path)
    print(f"JSON report saved to {json_path}")

    print("\nSummary:")
    print(f"  Total findings:   {summary['total_findings']}")
    print(f"  Auto-triaged:     {summary['auto_triaged_count']}")
    print(f"  Escalated:        {summary['escalated_count']}")
    print(f"  Severity breakdown: {summary['severity_distribution']}")


if __name__ == "__main__":
    generate_all_reports()