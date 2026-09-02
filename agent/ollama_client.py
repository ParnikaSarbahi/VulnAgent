"""LLM client with Groq API support and optional Ollama fallback."""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:32b")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))
TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))


def _groq_chat(messages, tools=None, stream=False):
    """Call Groq's OpenAI-compatible Chat Completions API.

    VulnAgent sends one tool definition at a time. Groq's GPT-OSS 20B does
    not support parallel tool use, so disable parallel calls explicitly.
    When a single tool is supplied, force that exact function so the
    deterministic Python orchestration receives the expected tool call.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set")

    payload = {
        "model": GROQ_MODEL,
        "messages": messages,
        "stream": stream,
        "temperature": TEMPERATURE,
    }
    if tools:
        payload["tools"] = tools
        payload["parallel_tool_calls"] = False
        if len(tools) == 1:
            payload["tool_choice"] = {
                "type": "function",
                "function": {"name": tools[0]["function"]["name"]},
            }

    response = requests.post(
        f"{GROQ_BASE_URL}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        json=payload,
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code != 200:
        print("Groq returned an error. Response body:")
        print(response.text)
    response.raise_for_status()
    data = response.json()

    message = data["choices"][0]["message"]
    return {"message": message, "raw_response": data}


def _ollama_chat(messages, tools=None, stream=False):
    """Call the local Ollama Chat API."""
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": stream,
        "options": {"temperature": TEMPERATURE},
    }
    if tools:
        payload["tools"] = tools

    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json=payload,
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code != 200:
        print("Ollama returned an error. Response body:")
        print(response.text)
    response.raise_for_status()
    return response.json()


def chat(messages, tools=None, stream=False):
    """Call the configured LLM backend.

    If GROQ_API_KEY is present, Groq is used. Otherwise the existing Ollama
    backend is used. Both return the response shape expected by agent_core.
    """
    if os.getenv("GROQ_API_KEY"):
        return _groq_chat(messages, tools=tools, stream=stream)
    return _ollama_chat(messages, tools=tools, stream=stream)


if __name__ == "__main__":
    result = chat([
        {"role": "user", "content": "Reply with exactly one sentence confirming you are working."}
    ])
    print(result["message"]["content"])
