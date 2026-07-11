# VulnAgent

**An autonomous, LLM-powered vulnerability triage agent.** VulnAgent ingests output from security scanners (Bandit SAST, Trivy container scanning, simulated OWASP ZAP DAST), uses a locally-hosted LLM with tool-use/function calling to classify severity, suggest fixes, and draft GitHub issues — and escalates to a human whenever severity is critical or model confidence is low. No manual triage per finding required.

Built end-to-end with a **free, local LLM (Ollama)** rather than a paid API, to demonstrate the agent architecture itself is the point — not access to a particular vendor's model.

![Security Scan CI](https://github.com/YOUR-USERNAME/VulnAgent/actions/workflows/security-scan.yml/badge.svg)

---

## Why this exists

Security teams are flooded with scanner findings across multiple tools. Manually triaging each one — judging severity, business impact, writing a fix, filing a ticket — doesn't scale. VulnAgent automates that pipeline while keeping a human in the loop exactly where it matters: low-confidence classifications and critical-severity findings.

## Architecture

```
 Scanner Output (Bandit / Trivy / simulated OWASP ZAP)
              │
              ▼
      ┌───────────────┐
      │  Parser Layer  │  scanners/ -- normalizes each tool's raw
      │                │  output into one common Finding schema
      └───────┬───────┘
              ▼
      ┌───────────────┐
      │  Agent Core    │  agent/ -- deterministic, code-controlled
      │  (tool-use)    │  triage sequence: classify -> branch ->
      │                │  remediate+ticket, OR escalate
      └───────┬───────┘
              ▼
   ┌──────────┴──────────┐
   │                      │
   ▼                      ▼
Auto-Triaged          Escalated to Human
(severity + fix        (confidence below
 + ticket draft)         threshold, OR
                          severity = CRITICAL)
              │
              ▼
      ┌───────────────┐
      │ Eval Layer     │  eval/ -- 20 labelled findings, measures
      │                │  triage accuracy against ground truth
      └───────┬───────┘
              ▼
      ┌───────────────┐
      │ Reports Layer  │  reports/ -- Markdown + JSON stakeholder
      │                │  reports, severity distribution chart
      └───────────────┘
              │
              ▼
      ┌───────────────┐
      │ CI/CD          │  .github/ -- Bandit runs on every push,
      │                │  fails the build on HIGH-severity findings
      └───────────────┘
```

### Why code, not the LLM, controls the sequence

An early version let the model freely decide which tool to call next across a multi-turn conversation. In practice, small local models lose track of multi-step plans — they'd classify a finding correctly, then just stop instead of continuing to remediation. The fix: **Python code enforces the triage sequence** (classify → branch on severity/confidence → remediate+ticket or escalate); the LLM only supplies reasoning and content *within* each forced step. This is a more robust pattern generally, not just a workaround for a small model.

## The four agent tools

| Tool | Input | Output |
|---|---|---|
| `classify_severity` | raw finding | severity, CVSS score, business impact, confidence level |
| `suggest_remediation` | classified finding | fix description, corrected code snippet, reference links |
| `generate_ticket` | classified + remediated finding | GitHub issue title, markdown body, priority, assignee placeholder |
| `escalate_to_human` | finding + confidence | escalation reason, context, urgency (persisted to `reports/escalations_log.jsonl`) |

## Tech stack

Python · **Ollama** (local LLM runtime, tool-use/function calling) · **Bandit** (SAST) · Trivy (container scanning) · simulated OWASP ZAP (DAST) · **pydantic** (schema validation) · **matplotlib** (reporting) · **GitHub Actions** (CI/CD)

## Setup

**Prerequisites:** Python 3.10+, [Ollama](https://ollama.com) installed with a tool-calling-capable model pulled.

```bash
git clone https://github.com/YOUR-USERNAME/VulnAgent.git
cd VulnAgent
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and set `OLLAMA_MODEL` to match a model you've pulled (`ollama list`). This project was developed and evaluated against `llama3.2:3b` for reliable tool-calling on modest hardware.

**Verify connectivity:**
```bash
python agent/ollama_client.py
```

## Running the full pipeline

```bash
# 1. Scan the sample vulnerable app with Bandit
bandit -f json -o samples/bandit_raw_output.json samples/vulnerable_app.py

# 2. Run the full triage agent over all findings
cd agent && python agent_core.py && cd ..

# 3. Generate stakeholder reports (Markdown + JSON + chart)
cd reports && python generate_report.py && cd ..

# 4. (Optional) Run the accuracy eval against 20 labelled findings
cd eval && python run_eval.py && cd ..
```

## Sample output

From a real run against `samples/vulnerable_app.py` (10 real Bandit findings):

> **Finding:** `[B602] subprocess call with shell=True identified, security issue.`
> - **Severity:** HIGH (CVSS 7.0)
> - **Business impact:** *"If exploited, an attacker could execute arbitrary commands on the system as the current user, potentially leading to unauthorized access or data tampering."*
> - **Recommended fix:** *"Use the subprocess module with the execve function instead of call, which is safer and more secure."*
> - **Ticket priority:** P1

Full output: [`reports/stakeholder_report.md`](reports/stakeholder_report.md) · [`reports/triage_results.json`](reports/triage_results.json) · [`reports/severity_chart.png`](reports/severity_chart.png)

## Eval results

Measured against 20 hand-labelled findings (10 real Bandit results + 10 synthetic findings covering vulnerability classes Bandit doesn't detect — SSRF, XXE, IDOR, hardcoded cloud credentials, etc.), scored against ground-truth severities assigned by manual security review:

| Metric | Result |
|---|---|
| Exact-match severity accuracy | 50.0% |
| Within-one-severity-level accuracy | 85.0% |
| Escalation accuracy (matches human judgment on what needs review) | 95.0% |
| CRITICAL-severity recall | 100% (3/3 caught) |
| CRITICAL-severity precision | 75% |

Full breakdown, including per-class precision/recall/F1: [`reports/eval_results.json`](reports/eval_results.json).

**What this shows, honestly:** the agent reliably catches genuinely critical findings (100% recall on CRITICAL) and rarely misses severity by more than one level (85%), but exact severity calibration on abstract/novel scenarios (vs. concrete code it can directly reason about) remains the weakest point — a real, documented limitation rather than a claimed 100% accuracy that wouldn't be credible anyway. Adding few-shot calibration examples to the system prompt measurably improved CRITICAL recall (from 33% to 100%) at a small cost to precision — evidence that this is at least partly a prompting/calibration problem, not purely a model-capability ceiling.

## CI/CD

`.github/workflows/security-scan.yml` runs Bandit on every push and PR, uploads the full JSON report as a build artifact, and **fails the build on any HIGH-severity finding** (LOW/MEDIUM are reported but non-blocking, matching realistic team policy — blocking on every minor finding creates alert fatigue). See `.github/scripts/check_bandit_severity.py` for the enforcement logic.

## Known limitations

- Small local models are unreliable at raw numeric self-confidence (fixed by eliciting a LOW/MEDIUM/HIGH label instead and mapping it to a number in code — see `tools/tool_implementations.py`).
- Multi-turn tool-use degrades once conversation history includes prior tool calls; fixed with explicit, single-step instructions rather than relying on the model to infer next steps (see `agent/agent_core.py`, `_call_single_tool`).
- Severity calibration on abstract/novel findings (no concrete code to reason about) is the primary remaining accuracy gap — see Eval Results above.
- Trivy and OWASP ZAP integration are simulated/stubbed for this project's scope; the parser layer is designed to make wiring in real scanner output a matter of adding one more parser, not restructuring the pipeline.

## Project structure

```
VulnAgent/
├── agent/            # Core agent loop + Ollama client
├── scanners/           # Bandit output parser + common Finding schema
├── tools/              # 4 tool definitions, implementations, diagnostics
├── eval/                # 20-finding labelled eval dataset + scorer
├── reports/             # Report generator + real generated output
├── samples/             # Sample vulnerable app + real Bandit scan output
├── .github/              # CI/CD workflow + severity gate script
└── requirements.txt
```

## License

MIT