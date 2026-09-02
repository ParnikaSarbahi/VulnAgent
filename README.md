# VulnAgent

**An autonomous, LLM-powered vulnerability triage agent.** VulnAgent ingests output from security scanners (Bandit SAST, Trivy vulnerability scanning, and OWASP ZAP DAST), normalizes findings into one schema, deduplicates them, uses a locally-hosted LLM with tool-use/function calling to classify severity, suggest fixes, and draft GitHub issues — and escalates to a human whenever severity is critical or model confidence is low.

Built end-to-end with a **free, local LLM (Ollama)** rather than a paid API, to demonstrate the agent architecture itself is the point — not access to a particular vendor's model.

![Security Scan CI](https://github.com/YOUR-USERNAME/VulnAgent/actions/workflows/security-scan.yml/badge.svg)

---

## Why this exists

Security teams are flooded with scanner findings across multiple tools. Manually triaging each one — judging severity, business impact, writing a fix, filing a ticket — doesn't scale. VulnAgent automates that pipeline while keeping a human in the loop exactly where it matters: low-confidence classifications and critical-severity findings.

## Architecture

```
 Scanner Execution (Bandit / Trivy / OWASP ZAP)
              │
              ▼
      ┌───────────────┐
      │  Parser Layer  │  scanners/ -- normalizes each tool's raw
      │                │  JSON output into one common Finding schema
      └───────┬───────┘
              ▼
      ┌───────────────┐
      │ Deduplication  │  cross-scanner fingerprinting prevents the
      │                │  same vulnerability being triaged repeatedly
      └───────┬───────┘
              ▼
      ┌───────────────┐
      │  Agent Core    │  deterministic, code-controlled triage:
      │  (tool-use)    │  classify -> branch -> remediate+ticket,
      │                │  OR escalate
      └───────┬───────┘
              ▼
   ┌──────────┴──────────┐
   │                     │
   ▼                     ▼
Auto-Triaged          Escalated to Human
(severity + fix        (low confidence,
 + ticket draft)         or CRITICAL)
              │
              ▼
      ┌───────────────┐
      │ Eval + Reports │
      └───────────────┘
```

### Why code, not the LLM, controls the sequence

An early version let the model freely decide which tool to call next across a multi-turn conversation. In practice, small local models lose track of multi-step plans — they'd classify a finding correctly, then just stop instead of continuing to remediation. The fix: **Python code enforces the triage sequence** (classify → branch on severity/confidence → remediate+ticket or escalate); the LLM only supplies reasoning and content *within* each forced step.

## Scanner integration

Each scanner has two responsibilities: execution and normalization.

| Scanner | Execution | Parser | Output |
|---|---|---|---|
| Bandit | `bandit -r ... -f json` | `scanners/bandit_parser.py` | `Finding` |
| Trivy | `trivy fs/image/rootfs/repo --format json` | `scanners/trivy_parser.py` | `Finding` |
| OWASP ZAP | `zap-baseline.py -t ... -J ...` | `scanners/zap_parser.py` | `Finding` |

`scanners/scanner_runner.py` executes only explicitly supplied targets and uses argument lists rather than shell commands. `scanners/scan_loader.py` runs the requested scanners, combines their normalized findings, and applies the deduplication layer.

The scanner binaries are intentionally **not bundled** with the Python package; they must be installed in the developer or CI environment. ZAP also requires an HTTP(S) application target.

## The four agent tools

| Tool | Input | Output |
|---|---|---|
| `classify_severity` | raw finding | severity, CVSS score, business impact, confidence level |
| `suggest_remediation` | classified finding | fix description, corrected code snippet, reference links |
| `generate_ticket` | classified + remediated finding | GitHub issue title, markdown body, priority, assignee placeholder |
| `escalate_to_human` | finding + confidence | escalation reason, context, urgency (persisted to `reports/escalations_log.jsonl`) |

## Tech stack

Python · **Ollama** (local LLM runtime, tool-use/function calling) · **Bandit** (SAST) · **Trivy** · **OWASP ZAP** · **pydantic** (schema validation) · **matplotlib** (reporting) · **GitHub Actions** (CI/CD)

## Setup

**Prerequisites:** Python 3.10+, [Ollama](https://ollama.com) installed with a tool-calling-capable model pulled. For real multi-scanner execution, also install Bandit, Trivy, and OWASP ZAP/ZAP baseline scan tooling.

```bash
git clone https://github.com/YOUR-USERNAME/VulnAgent.git
cd VulnAgent
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Edit your Ollama configuration as needed and verify connectivity:

```bash
python agent/ollama_client.py
```

## Running scanner ingestion

The runner can execute any subset of scanners. For example:

```python
from scanners.scan_loader import collect_findings

findings = collect_findings(
    bandit_target="samples/vulnerable_app.py",
    trivy_target=".",
    trivy_target_type="fs",
    zap_target_url="http://localhost:8000",
    output_dir="reports/scans",
)
```

Only provide `zap_target_url` when an application is actually running at that URL. For a container image, use `trivy_target_type="image"` and pass the image name as `trivy_target`.

For parser-only testing, the repository includes representative reports in `samples/trivy_raw_output.json` and `samples/zap_raw_output.json`, so tests do not require scanner binaries.

## Running the full pipeline

```bash
# 1. Generate Bandit output
bandit -r samples/vulnerable_app.py -f json -o samples/bandit_raw_output.json

# 2. Run the full triage agent over normalized findings
cd agent && python agent_core.py && cd ..

# 3. Generate stakeholder reports
cd reports && python generate_report.py && cd ..

# 4. Run the labelled evaluation
cd evals && python run_eval.py && cd ..
```

## Sample output

From a real run against `samples/vulnerable_app.py` (10 real Bandit findings):

> **Finding:** `[B602] subprocess call with shell=True identified, security issue.`
> - **Severity:** HIGH (CVSS 7.0)
> - **Business impact:** *"If exploited, an attacker could execute arbitrary commands on the system as the current user, potentially leading to unauthorized access or data tampering."*
> - **Recommended fix:** *"Use the subprocess module with the execve function instead of call, which is safer and more secure."*
> - **Ticket priority:** P1

Full output: `reports/stakeholder_report.md` · `reports/triage_results.json` · `reports/severity_chart.png`

## Eval results

Measured against 20 hand-labelled findings (10 real Bandit results + 10 synthetic findings covering vulnerability classes Bandit doesn't detect — SSRF, XXE, IDOR, hardcoded cloud credentials, etc.), scored against ground-truth severities assigned by manual security review:

| Metric | Result |
|---|---|
| Exact-match severity accuracy | 50.0% |
| Within-one-severity-level accuracy | 85.0% |
| Escalation accuracy (matches human judgment on what needs review) | 95.0% |
| CRITICAL-severity recall | 100% (3/3 caught) |
| CRITICAL-severity precision | 75% |

Full breakdown, including per-class precision/recall/F1: `reports/eval_results.json`.

**What this shows, honestly:** the agent reliably catches genuinely critical findings (100% recall on CRITICAL) and rarely misses severity by more than one level (85%), but exact severity calibration on abstract/novel scenarios remains the weakest point. This is a documented limitation rather than a claimed 100% accuracy.

## CI/CD

`.github/workflows/security-scan.yml` currently runs Bandit on every push and PR, uploads the full JSON report as a build artifact, and **fails the build on HIGH-severity findings**. Full Trivy/ZAP CI execution should be added once CI has a defined container target and deployed test web application; ZAP cannot be meaningfully run without an HTTP(S) target.

## Known limitations

- Small local models are unreliable at raw numeric self-confidence; the project therefore uses LOW/MEDIUM/HIGH confidence labels and maps them in code.
- Multi-turn tool-use can degrade with small local models; Python enforces the sequence instead of relying on model planning.
- Severity calibration on abstract/novel findings remains the primary evaluation gap.
- GitHub ticket generation currently produces a structured **ticket draft**, not a live GitHub Issue; live GitHub integration is Phase 3.
- Scanner execution depends on locally/CI-installed Bandit, Trivy, and ZAP binaries.

## Project structure

```
VulnAgent/
├── agent/              # Core agent loop + Ollama client
├── scanners/           # Scanner runners, parsers, schema + deduplication
├── tools/              # 4 tool definitions, implementations, diagnostics
├── evals/              # Labelled eval dataset + scorer
├── reports/            # Report generator + generated output
├── samples/            # Vulnerable app + scanner JSON fixtures
├── tests/              # Unit tests for scanner/deduplication components
├── .github/             # CI/CD workflow + severity gate script
└── requirements.txt
```

## License

MIT
