"""
tool_definitions.py

Defines the 4 tools as JSON schemas in the format Ollama's /api/chat
endpoint expects (same shape as OpenAI's function-calling format).

IMPORTANT: this file only defines the *shape* of each tool (name,
description, expected arguments) — it does NOT contain the logic. The
model reads these definitions and decides which tool to call and with
what arguments. The actual Python logic lives in tool_implementations.py.
Keeping these separate mirrors how real agent frameworks are structured:
schema (what the model sees) vs. implementation (what actually runs).
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "classify_severity",
            "description": (
                "Classify a security finding's severity. Given a finding's "
                "description and context, return a severity rating, an "
                "estimated CVSS score, and a short business impact statement."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "The assessed severity level."
                    },
                    "cvss_score": {
                        "type": "number",
                        "description": "Estimated CVSS v3 base score, 0.0 to 10.0."
                    },
                    "business_impact": {
                        "type": "string",
                        "description": "1-2 sentence plain-English explanation of real-world impact if exploited."
                    },
                    "confidence_level": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH"],
                        "description": (
                            "Your confidence in this classification. Use LOW only if the "
                            "finding is genuinely ambiguous or you lack context. Use HIGH "
                            "if the vulnerability type and impact are clear-cut. Use MEDIUM otherwise."
                        )
                    }
                },
                "required": ["severity", "cvss_score", "business_impact", "confidence_level"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_remediation",
            "description": (
                "Suggest a fix for a security finding. Return a description "
                "of the fix, a corrected code snippet, and reference links "
                "for further reading. Never introduce a hardcoded secret, "
                "password, token, API key, or unsafe default credential in "
                "the remediation example. For credential findings, use a "
                "secure secret source and fail safely when it is missing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "fix_description": {
                        "type": "string",
                        "description": "Plain-English explanation of how to fix the issue."
                    },
                    "code_snippet": {
                        "type": "string",
                        "description": "A corrected code example demonstrating the fix."
                    },
                    "reference_links": {
                        "type": "string",
                        "description": "Relevant reference URLs (docs, CWE pages, best-practice guides), separated by commas. Leave empty string if none apply."
                    }
                },
                "required": ["fix_description", "code_snippet", "reference_links"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_ticket",
            "description": (
                "Generate a GitHub issue draft for a security finding, "
                "ready to be filed in a tracker."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short, specific GitHub issue title."
                    },
                    "body_markdown": {
                        "type": "string",
                        "description": "Full issue body in markdown: summary, location, impact, suggested fix."
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["P0", "P1", "P2", "P3"],
                        "description": "Priority label, P0 = drop everything, P3 = backlog."
                    },
                    "assignee_placeholder": {
                        "type": "string",
                        "description": "Placeholder text for who should own this, e.g. '@security-team'."
                    }
                },
                "required": ["title", "body_markdown", "priority", "assignee_placeholder"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "escalate_to_human",
            "description": (
                "Escalate a finding to a human reviewer instead of auto-triaging it. "
                "Use this when confidence is low or severity is critical."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Why this needs human review (e.g. 'low confidence', 'critical severity')."
                    },
                    "context": {
                        "type": "string",
                        "description": "Relevant details the human reviewer needs to make a fast decision."
                    },
                    "urgency": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH", "IMMEDIATE"],
                        "description": "How quickly a human needs to look at this."
                    }
                },
                "required": ["reason", "context", "urgency"]
            }
        }
    }
]
