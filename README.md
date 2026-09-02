# VulnAgent

**An autonomous, LLM-powered vulnerability triage agent.** VulnAgent ingests security-scanner output (Bandit SAST, Trivy vulnerability scanning, and OWASP ZAP DAST), normalizes findings into one schema, deduplicates them, uses a locally hosted LLM with tool calling to classify severity and suggest fixes, then creates GitHub issues or PR comments when explicitly enabled. Critical or low-confidence findings are escalated to a human.

Built end-to-end with a **local LLM (Ollama)** so the agent workflow does not depend on a paid model API.

![Security Scan CI](https://github.com/ParnikaSarbahi/VulnAgent/actions/workflows/security-scan.yml/badge.svg)

---

## Architecture

```text
Bandit / Trivy / OWASP ZAP
          │
          ▼
   Parser + Finding schema
          │
          ▼
     Deduplication
          │
          ▼
      Agent Core
 classify → branch → remediate → ticket
                 │
          ┌──────┴──────┐
          ▼             ▼
       GitHub        Human review
       issue/PR      for CRITICAL or
       comment       low confidence
```

Python controls the workflow order. The LLM supplies security assessment and remediation content inside each forced step, which makes the pipeline more predictable than letting a small local model plan the entire multi-turn workflow.

## Scanner integration

| Scanner | Execution | Parser | Output |
|---|---|---|---|
| Bandit | `bandit -r ... -f json` | `scanners/bandit_parser.py` | `Finding` |
| Trivy | `trivy fs/image/rootfs/repo --format json` | `scanners/trivy_parser.py` | `Finding` |
| OWASP ZAP | `zap-baseline.py -t ... -J ...` | `scanners/zap_parser.py` | `Finding` |

`scanners/scanner_runner.py` executes only explicitly supplied targets using subprocess argument lists. `scanners/scan_loader.py` combines normalized findings and deduplicates them. Scanner binaries are not bundled with the project.

## Agent tools

| Tool | Purpose |
|---|---|
| `classify_severity` | Severity, estimated CVSS, business impact, confidence |
| `suggest_remediation` | Code-level fix and references |
| `generate_ticket` | Ticket content plus optional live GitHub Issue/PR comment |
| `escalate_to_human` | Human-review record persisted to `reports/escalations_log.jsonl` |

## Setup

Prerequisites: Python 3.10+, Ollama with a tool-calling-capable model, and the scanner binaries for scanners you intend to execute.

```bash
git clone https://github.com/ParnikaSarbahi/VulnAgent.git
cd VulnAgent
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Configure Ollama through environment variables when needed:

```bash
export OLLAMA_BASE_URL=http://localhost:11434
export OLLAMA_MODEL=qwen3:32b
export OLLAMA_TIMEOUT_SECONDS=120
```

Verify the model connection:

```bash
python agent/ollama_client.py
```

## Running the pipeline

The root CLI is the recommended entrypoint.

Use an existing Bandit report:

```bash
python run_vulnagent.py \
  --bandit-report samples/bandit_raw_output.json \
  --output reports/triage_results.json
```

Or execute Bandit directly through VulnAgent:

```bash
python run_vulnagent.py \
  --bandit-target samples/vulnerable_app.py \
  --output reports/triage_results.json
```

Run additional scanners when their binaries and targets are available:

```bash
python run_vulnagent.py \
  --bandit-target samples/vulnerable_app.py \
  --trivy-target . \
  --trivy-type fs \
  --zap-url http://localhost:8000
```

ZAP requires an actually running HTTP(S) application. For Trivy images, use `--trivy-type image` and pass the image name as the target.

By default, GitHub side effects are **disabled**. The pipeline produces ticket drafts only unless the GitHub environment flags below are enabled.

## Enabling GitHub integration

For live GitHub Issues:

```bash
export GITHUB_TOKEN=<token>
export GITHUB_REPOSITORY=owner/repository
export VULNAGENT_CREATE_GITHUB_ISSUES=true
```

For a PR comment:

```bash
export GITHUB_TOKEN=<token>
export GITHUB_REPOSITORY=owner/repository
export GITHUB_PR_NUMBER=123
export VULNAGENT_COMMENT_ON_PR=true
```

Both flags may be enabled together. The client validates repository/PR inputs and uses an idempotency marker for finding-derived issues, so repeated runs do not create the same issue again. Use a token with the repository permissions required for the actions you enable.

## Tests

The automated suite is deliberately independent of Ollama, Trivy, and ZAP. It mocks the LLM path and uses scanner JSON fixtures, so CI can validate orchestration without external services.

```bash
pytest -q
```

Manual model experiments belong outside pytest and require a running Ollama server.

## Reports and evaluation

Stakeholder reports are generated from `reports/triage_results.json`:

```bash
python reports/generate_report.py
```

The repository also contains a 20-finding labelled evaluation set. The current recorded results are:

| Metric | Result |
|---|---|
| Exact-match severity accuracy | 50.0% |
| Within-one-severity-level accuracy | 85.0% |
| Escalation accuracy | 95.0% |
| CRITICAL recall | 100% (3/3) |
| CRITICAL precision | 75% |

These are baseline evaluation results, not a claim of production-level accuracy. Severity calibration on abstract/novel findings remains the main limitation.

## CI/CD

`.github/workflows/security-scan.yml` runs the automated test suite first. It then produces a full Bandit report as an artifact and applies the HIGH/CRITICAL severity gate to the production code paths. The intentionally vulnerable files under `samples/` remain available as demonstration fixtures without making the repository's own CI permanently red.

Trivy and ZAP are not executed in CI because this repository does not define a container image or deployed web application target. Their parsers are covered by fixture-based tests.

## Current MVP scope

Included:

- Bandit, Trivy, and ZAP normalization
- Cross-scanner finding deduplication
- Deterministic LLM triage flow
- Critical/low-confidence human escalation
- Incremental result saving
- GitHub Issue creation with duplicate protection
- Optional PR comments
- Automated tests and CI severity enforcement
- CLI for end-to-end execution

Not included yet:

- SQLite/persistent vulnerability lifecycle database
- Automated fix application and rescan verification
- Large-scale evaluation dataset and confidence calibration
- Webhook/API service, dashboard, and production observability

Those are subsequent phases; the current branch is intentionally a **database-free, merge-ready MVP**.

## Project structure

```text
VulnAgent/
├── agent/              # Agent orchestration + Ollama client
├── scanners/           # Runners, parsers, schema, deduplication
├── integrations/       # GitHub API integration + PR formatting
├── tools/              # Tool schemas and implementations
├── evals/              # Labelled evaluation dataset + scorer
├── reports/            # Report generation and output
├── samples/            # Vulnerable app + scanner fixtures
├── tests/              # Automated tests
├── .github/             # CI workflow + severity gate
├── run_vulnagent.py    # End-to-end CLI
└── requirements.txt
```

## License

MIT
