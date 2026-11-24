import json
import sys
from pathlib import Path

import pytest

from reviewer.agent import RootAgent
from reviewer.approval import ApprovalGate, issue_token, verify_token
from reviewer.audit import AuditLog
from reviewer.llm import LLMError, OllamaClient
from reviewer.mcp_client import McpClient, McpUnavailable, ToolTimeout
from reviewer.schemas import ReviewRequest

SECRET = "s3cret"
REQ = ReviewRequest("./demo", "abc1234567890", "owner/security-demo")
FAKE_KEY = "AKIAABCDEFGHIJKLMNOP"


def ok(data, summary="ok"):
    return {"success": True, "summary": summary, "data": data, "error": None}


FINDING = {"rule": "api_token", "file": "config.py", "line": 3, "evidence": "API_KEY = 'AK****'",
           "severity": "HIGH", "confidence": "high"}


class Calls(dict):
    def __missing__(self, k):
        return 0


class FakeClient:
    """In-process stand-in for McpClient (same 4 methods)."""

    def __init__(self, findings=(FINDING,), files=("config.py",), diff_fail=0, issue=None,
                 tools=None, fail_start=False):
        self.findings, self.files, self.diff_fail, self.issue = findings, files, diff_fail, issue
        self.tools = tools or ["get_commit_diff", "scan_commit", "create_security_issue"]
        self.fail_start, self.calls = fail_start, Calls()

    def start(self):
        if self.fail_start:
            raise McpUnavailable("no server")

    def list_tools(self):
        return self.tools

    def close(self):
        pass

    def call_tool(self, name, a, timeout):
        self.calls[name] += 1
        if name == "get_commit_diff":
            if self.calls[name] <= self.diff_fail:
                raise ToolTimeout("slow")
            return ok({"diff_handle": "h1", "changed_files": list(self.files)})
        if name == "scan_commit":
            return ok({"findings": list(self.findings)})
        good, why = verify_token(SECRET, a["approval_token"], a["repository"], a["commit_id"])
        if not good:
            return {"success": False, "summary": why, "data": {}, "error": why}
        return self.issue or ok({"issue_number": 12,
                                 "issue_url": f"https://github.com/{a['github_repo']}/issues/12"})


def agent(tmp_path, client, answer="yes", llm=None):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    prompts = []

    def fake_input(p):
        prompts.append(p)
        return answer

    gate = ApprovalGate(SECRET, input_fn=fake_input, output_fn=lambda s: None)
    return RootAgent(client, gate, audit, llm=llm), audit, prompts


def test_yes_creates_verified_issue(tmp_path):
    c = FakeClient()
    a, _, prompts = agent(tmp_path, c, "yes")
    out = a.run(REQ)
    assert out.status == "issue_created" and out.issue_number == 12
    assert out.diagnosis.severity == "HIGH" and len(prompts) == 1
    assert c.calls["create_security_issue"] == 1


def test_no_creates_nothing(tmp_path):
    c = FakeClient()
    out = agent(tmp_path, c, "no")[0].run(REQ)
    assert out.status == "declined" and c.calls["create_security_issue"] == 0


def test_clean_commit_no_prompt(tmp_path):
    c = FakeClient(findings=())
    a, _, prompts = agent(tmp_path, c)
    assert a.run(REQ).status == "clean" and prompts == [] and c.calls["create_security_issue"] == 0


def test_timeout_one_retry_then_success(tmp_path):
    c = FakeClient(diff_fail=1)
    assert agent(tmp_path, c)[0].run(REQ).status == "issue_created"
    assert c.calls["get_commit_diff"] == 2


def test_timeout_twice_stops_safely(tmp_path):
    c = FakeClient(diff_fail=99)
    a, _, prompts = agent(tmp_path, c)
    assert a.run(REQ).status == "failed" and prompts == [] and c.calls["get_commit_diff"] == 2


def test_mcp_unavailable_stops_and_logs(tmp_path):
    a, audit, prompts = agent(tmp_path, FakeClient(fail_start=True))
    out = a.run(REQ)
    assert out.status == "failed" and prompts == []
    assert any(e["event"] == "mcp_connect" and "FAILED" in e["outcome"] for e in audit.entries)


def test_missing_required_tool_stops(tmp_path):
    out = agent(tmp_path, FakeClient(tools=["get_commit_diff"]))[0].run(REQ)
    assert out.status == "failed" and "missing" in out.message


def test_issue_not_retried_and_unverifiable_success_rejected(tmp_path):
    c = FakeClient(issue=ok({"issue_number": 5, "issue_url": "https://evil.example/5"}))
    out = agent(tmp_path, c)[0].run(REQ)
    assert out.status == "failed" and c.calls["create_security_issue"] == 1


def test_agent_refuses_issue_call_without_token(tmp_path):
    c = FakeClient()
    a, _, _ = agent(tmp_path, c)
    res = a._call("create_security_issue", {"repository": "r", "commit_id": "c"}, "test")
    assert not res.success and res.error == "approval_required" and c.calls["create_security_issue"] == 0


def test_token_expiry_wrong_commit_and_single_use():
    t = issue_token(SECRET, "r", "c", ttl=60)
    used: set = set()
    assert verify_token(SECRET, t, "r", "c", used)[0]
    assert not verify_token(SECRET, t, "r", "c", used)[0]
    assert not verify_token(SECRET, t, "r", "other")[0]
    assert not verify_token(SECRET, issue_token(SECRET, "r", "c", ttl=-1), "r", "c")[0]


def test_audit_has_no_secrets_or_tokens(tmp_path):
    c = FakeClient(findings=(dict(FINDING, evidence=f"key = '{FAKE_KEY}'"),))
    agent(tmp_path, c)[0].run(REQ)
    log = (tmp_path / "audit.jsonl").read_text()
    assert FAKE_KEY not in log
    assert all(json.loads(l)["ts"] for l in log.splitlines())
    assert '"approval_token": "<omitted>"' in log


def test_real_mcp_end_to_end(tmp_path):
    pytest.importorskip("mcp")
    stub = str(Path(__file__).parent / "stub_server.py")
    client = McpClient(sys.executable, [stub], env={"REVIEWER_APPROVAL_SECRET": SECRET})
    out = agent(tmp_path, client)[0].run(REQ)
    assert out.status == "issue_created", out.message


class FakeLLM:
    model = "fake"

    def __init__(self, out=None, fail=False):
        self.out, self.fail, self.seen = out, fail, ""

    def chat_json(self, system, user):
        self.seen = user
        if self.fail:
            raise LLMError("ollama down")
        return self.out


def test_llm_enriches_but_cannot_change_severity_or_findings(tmp_path):
    llm = FakeLLM({"risk": f"Leaked {FAKE_KEY} grants access.", "recommendation": "Rotate it.",
                   "confidence": "low", "needs_review": True})
    a, audit, _ = agent(tmp_path, FakeClient(), "no", llm=llm)
    out = a.run(REQ)
    d = out.diagnosis
    assert d.severity == "HIGH" and len(d.findings) == 1          # unchanged
    assert d.recommendation == "Rotate it." and d.confidence == "low" and d.needs_review
    assert FAKE_KEY not in d.risk                                  # model output scrubbed
    assert FAKE_KEY not in (tmp_path / "audit.jsonl").read_text()


def test_llm_cannot_raise_confidence_or_clear_needs_review(tmp_path):
    f = dict(FINDING, confidence="low")
    llm = FakeLLM({"risk": "ok", "recommendation": "fix", "confidence": "high", "needs_review": False})
    out = agent(tmp_path, FakeClient(findings=(f,)), "no", llm=llm)[0].run(REQ)
    assert out.diagnosis.confidence == "low" and out.diagnosis.needs_review


def test_llm_failure_falls_back_and_flow_continues(tmp_path):
    a, audit, prompts = agent(tmp_path, FakeClient(), "yes", llm=FakeLLM(fail=True))
    out = a.run(REQ)
    assert out.status == "issue_created" and len(prompts) == 1
    assert any(e["event"] == "llm_call" and "FAILED" in e["outcome"] for e in audit.entries)


def test_llm_not_called_on_clean_commit(tmp_path):
    llm = FakeLLM({"risk": "x", "recommendation": "y"})
    agent(tmp_path, FakeClient(findings=()), llm=llm)[0].run(REQ)
    assert llm.seen == ""


def test_ollama_client_http_roundtrip_and_errors():
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            req = _json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert req["format"] == "json" and req["stream"] is False and req["model"] == "m1"
            body = _json.dumps({"message": {"content": _json.dumps({"risk": "r"})}}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = OllamaClient("m1", f"127.0.0.1:{srv.server_port}", timeout=5)
    assert c.chat_json("s", "u") == {"risk": "r"}
    srv.shutdown()
    srv.server_close()
    with pytest.raises(LLMError):
        OllamaClient("m1", "http://127.0.0.1:1", timeout=2).chat_json("s", "u")
