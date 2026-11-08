"""Swappable model backends. Anything that maps (system, user) -> text works.

- AnthropicBackend: Claude via the official SDK (needs ANTHROPIC_API_KEY).
- OllamaBackend:    a local open model, $0, for development.
- The triage layer also has a no-LLM heuristic baseline, so the pipeline never depends on a model.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Protocol


class LLMBackend(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str: ...


class AnthropicBackend:
    def __init__(self, model: str | None = None, max_tokens: int = 800):
        import anthropic  # imported lazily so the package works without it

        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        self.model = model or os.environ.get("VRA_MODEL", "claude-haiku-5-5")
        self.max_tokens = max_tokens
        self.name = f"anthropic:{self.model}"

    def complete(self, system: str, user: str) -> str:
        resp = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


class OllamaBackend:
    def __init__(self, model: str | None = None, host: str | None = None):
        self.model = model or os.environ.get("VRA_OLLAMA_MODEL", "llama3.1")
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.name = f"ollama:{self.model}"

    def complete(self, system: str, user: str) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "stream": False,
                "format": "json",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.host}/api/chat", data=body, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())["message"]["content"]


def get_backend(name: str) -> LLMBackend | None:
    if name == "heuristic":
        return None
    if name == "anthropic":
        return AnthropicBackend()
    if name == "ollama":
        return OllamaBackend()
    raise ValueError(f"unknown backend {name!r} (use heuristic, anthropic or ollama)")
