"""LLM client with Groq API support and optional Ollama fallback."""

import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:32b")
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.2"))
TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
GROQ_MAX_RETRIES = int(os.getenv("GROQ_MAX_RETRIES", "4"))
GROQ_MAX_COMPLETION_TOKENS = int(os.getenv("GROQ_MAX_COMPLETION_TOKENS", "600"))


def _retry_delay(response, attempt):
    """Return a bounded delay using Groq's rate-limit headers when available."""
    retry_after = response.headers.get("retry-after")
    if retry_after:
        try:
            return min(float(retry_after), 60.0)
        except ValueError:
            pass

    reset_tokens = response.headers.get("x-ratelimit-reset-tokens")
    if reset_tokens:
        value = reset_tokens.strip().lower()
        try:
            if value.endswith("ms"):
                return min(float(value[:-2]) / 1000.0, 60.0)
            if value.endswith("s"):
                return min(float(value[:-1]), 60.0)
            if value.endswith("m"):
                return min(float(value[:-1]) * 60.0, 60.0)
        except ValueError:
            pass

    return min(2.0 ** attempt, 30.0)


def _groq_chat(messages, tools=None, stream=False):
    """Call Groq's OpenAI-compatible Chat Completions API with 429 retries."""
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set")

    payload = {
        "model": GROQ_MODEL,
        "messages": messages,
        "stream": stream,
        "temperature": TEMPERATURE,
        "max_completion_tokens": GROQ_MAX_COMPLETION_TOKENS,
    }
    if tools:
        payload["tools"] = tools
        payload["parallel_tool_calls"] = False
        if len(tools) == 1:
            # "required" avoids provider-specific validation issues with a
            # forced function object while still guaranteeing a tool call.
            payload["tool_choice"] = "required"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    for attempt in range(GROQ_MAX_RETRIES + 1):
        response = requests.post(
            f"{GROQ_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )

        if response.status_code == 429 and attempt < GROQ_MAX_RETRIES:
            delay = _retry_delay(response, attempt)
            print(
                f"Groq rate limit reached (attempt {attempt + 1}/{GROQ_MAX_RETRIES}). "
                f"Retrying in {delay:.1f}s."
            )
            time.sleep(delay)
            continue

        if response.status_code != 200:
            print("Groq returned an error. Response body:")
            print(response.text)
            request_id = response.headers.get("x-request-id") or response.headers.get("x-groq-request-id")
            request_suffix = f"; request_id={request_id}" if request_id else ""
            raise RuntimeError(
                f"Groq HTTP {response.status_code}: {response.text}{request_suffix}"
            )

        data = response.json()
        message = data["choices"][0]["message"]
        return {"message": message, "raw_response": data}

    raise RuntimeError("Groq request failed after retry attempts")


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
