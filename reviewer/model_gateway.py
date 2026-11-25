"""Model gateway: the ONLY place that knows which LLM is used and how to reach it.

    gw = ModelGateway("local")      # Ollama on this machine; started on demand
    gw = ModelGateway("copilot")    # GitHub Models API (OpenAI-compatible), needs a token
    gw.start(); gw.chat_json(system, user); gw.close()

The agent only calls chat_json() / .label. Providers, URLs, tokens and defaults live here.
Only already-redacted findings are ever sent to a model.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urlparse

from .llm import DEFAULT_HOST, DEFAULT_MODEL, LLMError, OllamaClient

log = logging.getLogger("agent")

PROVIDERS = ("local", "copilot")
COPILOT_URL = "https://models.github.ai/inference/chat/completions"
COPILOT_DEFAULT_MODEL = "openai/gpt-4.1"
COPILOT_TOKEN_ENV = "GITHUB_MODELS_TOKEN"          # PAT with 'models: read'; NOT the issue token
COPILOT_URL_ENV = "GITHUB_MODELS_URL"
MODEL_NAME_ENV = "REVIEWER_MODEL"
OLLAMA_START_WAIT = 20.0


class ModelGateway:
    def __init__(self, provider: str = "local", model_name: Optional[str] = None,
                 timeout: float = 60.0):
        provider = (provider or "local").lower()
        if provider not in PROVIDERS:
            raise ValueError(f"model must be one of {', '.join(PROVIDERS)} (got {provider!r})")
        self.provider, self.timeout = provider, timeout
        name = model_name or os.environ.get(MODEL_NAME_ENV)
        if provider == "local":
            self.model = name or DEFAULT_MODEL
            self._ollama = OllamaClient(self.model, timeout=timeout)
            self.host = self._ollama.host
        else:
            # a local default like llama3.1 makes no sense for copilot, so only use an explicit name
            self.model = model_name or COPILOT_DEFAULT_MODEL
            self.url = os.environ.get(COPILOT_URL_ENV, COPILOT_URL)
        self._proc: Optional[subprocess.Popen] = None

    @property
    def label(self) -> str:
        return f"{'ollama' if self.provider == 'local' else 'copilot'}:{self.model}"

    # ------------------------------------------------------------ lifecycle --
    def start(self) -> None:
        """Make the model reachable. Raises LLMError if it cannot be."""
        if self.provider == "local":
            self._start_ollama()
        else:
            self._token()                        # fail early with a clear message
            log.info("model gateway: %s via %s", self.label, self.url)

    def close(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            log.info("model gateway: stopping the ollama server we started")
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def _ollama_up(self) -> bool:
        try:
            with urllib.request.urlopen(self.host, timeout=2):
                return True
        except Exception:
            return False

    def _start_ollama(self) -> None:
        if self._ollama_up():
            log.info("model gateway: ollama already running at %s (model %s)", self.host, self.model)
            return
        if urlparse(self.host).hostname not in ("localhost", "127.0.0.1", "::1"):
            raise LLMError(f"Ollama not reachable at {self.host} (remote hosts are not started)")
        exe = shutil.which("ollama")
        if not exe:
            raise LLMError("Ollama is not running and 'ollama' is not on PATH - install it from ollama.com")
        log.info("model gateway: starting 'ollama serve' ...")
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
        self._proc = subprocess.Popen([exe, "serve"], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, creationflags=flags)
        deadline = time.monotonic() + OLLAMA_START_WAIT
        while time.monotonic() < deadline:
            if self._ollama_up():
                log.info("model gateway: ollama started (model %s; first call may be slow)", self.model)
                return
            if self._proc.poll() is not None:
                break
            time.sleep(0.5)
        self.close()
        raise LLMError(f"'ollama serve' did not become ready within {OLLAMA_START_WAIT:.0f}s")

    # ----------------------------------------------------------------- chat --
    def chat_json(self, system: str, user: str) -> dict[str, Any]:
        if self.provider == "local":
            return self._ollama.chat_json(system, user)
        return self._copilot_chat_json(system, user)

    def _token(self) -> str:
        tok = os.environ.get(COPILOT_TOKEN_ENV, "").strip()
        if not tok:
            raise LLMError(f"model=copilot needs {COPILOT_TOKEN_ENV} in .env "
                           "(fine-grained GitHub token with 'models: read')")
        return tok

    def _copilot_chat_json(self, system: str, user: str) -> dict[str, Any]:
        body = json.dumps({
            "model": self.model, "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "security-commit-reviewer"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.load(resp)
            out = json.loads(payload["choices"][0]["message"]["content"])
        except urllib.error.HTTPError as exc:
            hints = {401: "token invalid or expired", 403: "token lacks 'models: read'",
                     404: f"model {self.model!r} not found in the GitHub Models catalog",
                     429: "rate limited - try again later"}
            raise LLMError(f"GitHub Models returned HTTP {exc.code}: {hints.get(exc.code, '')}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(f"GitHub Models unreachable: {exc}") from exc
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            raise LLMError(f"Unusable GitHub Models response: {exc!r}") from exc
        if not isinstance(out, dict):
            raise LLMError("Model did not return a JSON object")
        return out
