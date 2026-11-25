"""Local LLM via Ollama's REST API (stdlib only, synchronous).

Ollama must be running (`ollama serve`) and the model pulled (`ollama pull <model>`).
Only already-redacted findings are ever sent here.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1"


class LLMError(Exception):
    """Ollama unreachable, timed out, or returned unusable output."""


class OllamaClient:
    def __init__(self, model: Optional[str] = None, host: Optional[str] = None,
                 timeout: float = 60.0):
        self.model = model or os.environ.get("REVIEWER_MODEL", DEFAULT_MODEL)
        self.host = (host or os.environ.get("OLLAMA_HOST", DEFAULT_HOST)).rstrip("/")
        if not self.host.startswith("http"):
            self.host = "http://" + self.host
        self.timeout = timeout

    def chat_json(self, system: str, user: str) -> dict[str, Any]:
        """One chat turn that must answer with a JSON object. Deterministic (temperature 0)."""
        body = json.dumps({
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(f"{self.host}/api/chat", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.load(resp)
            content = payload["message"]["content"]
            out = json.loads(content)
        except urllib.error.HTTPError as exc:      # Ollama answered with an error (e.g. 404 model not pulled)
            try:
                detail = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                detail = ""
            hint = f" - run `ollama pull {self.model}` or pick a model from `ollama list`" if exc.code == 404 else ""
            raise LLMError(f"Ollama returned HTTP {exc.code}: {detail}{hint}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(f"Ollama unreachable at {self.host}: {exc}") from exc
        except (KeyError, ValueError) as exc:
            raise LLMError(f"Unusable Ollama response: {exc!r}") from exc
        if not isinstance(out, dict):
            raise LLMError("Model did not return a JSON object")
        return out
