import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from reviewer.llm import LLMError
from reviewer.model_gateway import COPILOT_TOKEN_ENV, COPILOT_URL_ENV, ModelGateway


def _server(handler):
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_bad_provider_and_labels(monkeypatch):
    monkeypatch.delenv("REVIEWER_MODEL", raising=False)
    with pytest.raises(ValueError):
        ModelGateway("gpt")
    assert ModelGateway("local").label == "ollama:llama3.1"
    assert ModelGateway("copilot").label == "copilot:openai/gpt-4.1"
    assert ModelGateway("local", "qwen").label == "ollama:qwen"


def test_copilot_requires_token(monkeypatch):
    monkeypatch.delenv(COPILOT_TOKEN_ENV, raising=False)
    with pytest.raises(LLMError, match=COPILOT_TOKEN_ENV):
        ModelGateway("copilot").start()


def test_copilot_roundtrip_sends_token_and_parses(monkeypatch):
    seen = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            seen["auth"] = self.headers["Authorization"]
            seen["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            out = json.dumps({"choices": [{"message": {"content": json.dumps({"risk": "r"})}}]}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers()
            self.wfile.write(out)
        def log_message(self, *a): pass

    srv = _server(H)
    monkeypatch.setenv(COPILOT_TOKEN_ENV, "tok123")
    monkeypatch.setenv(COPILOT_URL_ENV, f"http://127.0.0.1:{srv.server_port}/x")
    gw = ModelGateway("copilot", timeout=5)
    gw.start()
    assert gw.chat_json("sys", "usr") == {"risk": "r"}
    assert seen["auth"] == "Bearer tok123" and seen["body"]["model"] == "openai/gpt-4.1"
    srv.shutdown(); srv.server_close()


def test_copilot_http_error_hint(monkeypatch):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(403); self.send_header("Content-Length", "0"); self.end_headers()
        def log_message(self, *a): pass

    srv = _server(H)
    monkeypatch.setenv(COPILOT_TOKEN_ENV, "t")
    monkeypatch.setenv(COPILOT_URL_ENV, f"http://127.0.0.1:{srv.server_port}")
    with pytest.raises(LLMError, match="403.*models: read"):
        ModelGateway("copilot", timeout=5).chat_json("s", "u")
    srv.shutdown(); srv.server_close()


def test_local_already_running_is_not_started_or_stopped(monkeypatch):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *a): pass

    srv = _server(H)
    monkeypatch.setenv("OLLAMA_HOST", f"127.0.0.1:{srv.server_port}")
    gw = ModelGateway("local")
    gw.start()
    assert gw._proc is None
    gw.close()
    srv.shutdown(); srv.server_close()


def test_local_not_running_and_no_binary(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:1")
    monkeypatch.setattr("reviewer.model_gateway.shutil.which", lambda _: None)
    with pytest.raises(LLMError, match="not on PATH"):
        ModelGateway("local").start()


def test_local_starts_ollama_serve_and_stops_it(monkeypatch):
    import reviewer.model_gateway as mg
    monkeypatch.setenv("OLLAMA_HOST", "127.0.0.1:1")
    monkeypatch.setattr(mg.shutil, "which", lambda _: "ollama")
    ups = iter([False, False, True])
    gw = ModelGateway("local")
    monkeypatch.setattr(gw, "_ollama_up", lambda: next(ups))
    monkeypatch.setattr(mg.time, "sleep", lambda _: None)

    class P:
        terminated = False
        def poll(self): return None
        def terminate(self): P.terminated = True
        def wait(self, timeout=None): pass

    started = {}
    monkeypatch.setattr(mg.subprocess, "Popen", lambda cmd, **k: started.setdefault("cmd", cmd) and P())
    gw.start()
    assert started["cmd"] == ["ollama", "serve"]
    gw.close()
    assert P.terminated
