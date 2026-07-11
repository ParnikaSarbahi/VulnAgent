"""
ollama_client.py

Thin wrapper around Ollama's local HTTP API. Every other part of VulnAgent
(tool-use, agent loop) will call through this module instead of hitting
`requests` directly — that way, if we ever swap models or endpoints, we
only change one file.

Ollama exposes an OpenAI-style chat endpoint at:
    POST http://localhost:11434/api/chat

We send it a list of messages (and later, tool definitions) and get back
a JSON response containing the model's reply.
"""

import os
import requests
from dotenv import load_dotenv

# Load variables from .env into the environment
load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:32b")
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.2"))
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "120"))


def chat(messages, tools=None, stream=False):
    """
    Send a chat request to the local Ollama server.

    Args:
        messages: list of {"role": "user"|"assistant"|"system", "content": str}
        tools: optional list of tool definitions (used from Step 3 onward)
        stream: if False, we get the full response in one shot (simplest
                for a first test — we'll consider streaming later if needed)

    Returns:
        The parsed JSON response from Ollama.
    """
    url = f"{OLLAMA_BASE_URL}/api/chat"

    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": stream,
        "options": {
            "temperature": OLLAMA_TEMPERATURE
        }
    }

    if tools:
        payload["tools"] = tools

    response = requests.post(url, json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)

    if response.status_code != 200:
        # Print the actual error body from Ollama before raising, so we can
        # see *why* it failed (bad model name, malformed request, etc.)
        # instead of just seeing a generic "500 Server Error".
        print("Ollama returned an error. Response body:")
        print(response.text)

    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    # Quick manual test: python agent/ollama_client.py
    result = chat([
        {"role": "user", "content": "Reply with exactly one sentence confirming you are working."}
    ])
    print(result["message"]["content"])