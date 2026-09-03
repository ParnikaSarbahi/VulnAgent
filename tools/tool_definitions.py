"""
tool_definitions.py

Defines the 4 tools as JSON schemas in the format Ollama's /api/chat
endpoint expects (same shape as OpenAI's function-calling format).

This file defines tool schemas only; implementations live in
``tool_implementations.py``.
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "classify_severity",
            "description": (
                "Classify a security finding. Return severity, estimated CVSS v3 base score, "
                "short business impact, and confidence."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                    "cvss_score": {"type": "number", "description": "Estimated CVSS v3 base score, 0.0 to 10.0."},
                    "business_impact": {"type": "string", "description": "1-2 sentence plain-English impact."},
                    "confidence_level": {
                        "type": "string",
                        "enum": ["LOW", "MEDIUM", "HIGH"],
                        "description": "Confidence in the classification."
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
                "Suggest a focused fix. Return a concise fix description, corrected code example, "
                "and relevant reference links. Never introduce hardcoded secrets, passwords, tokens, "
                "API keys, or unsafe default credentials; credential fixes must use a secure secret source."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "fix_description": {"type": "string", "description": "Plain-English fix explanation."},
                    "code_snippet": {"type": "string", "description": "Concise corrected code example."},
                    "reference_links": {"type": "string", "description": "Relevant URLs separated by commas; empty if none."}
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
                "Generate a concise GitHub issue draft. Keep the title to 12 words or fewer and the body "
                "to about 180 words or fewer. Include only summary, exact location, impact, suggested fix, "
                "and key references. Avoid long code blocks, repetition, and filler so the JSON arguments "
                "remain compact and valid."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short, specific title, 12 words or fewer."},
                    "body_markdown": {
                        "type": "string",
                        "description": "Concise body, about 180 words or fewer; no long code blocks or repetition."
                    },
                    "priority": {"type": "string", "enum": ["P0", "P1", "P2", "P3"]},
                    "assignee_placeholder": {"type": "string", "description": "Ownership placeholder, e.g. '@security-team'."}
                },
                "required": ["title", "body_markdown", "priority", "assignee_placeholder"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "escalate_to_human",
            "description": "Escalate a finding to a human reviewer when confidence is low or severity is critical.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {"type": "string", "description": "Why human review is needed."},
                    "context": {"type": "string", "description": "Relevant details for the reviewer."},
                    "urgency": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "IMMEDIATE"]}
                },
                "required": ["reason", "context", "urgency"]
            }
        }
    }
]
