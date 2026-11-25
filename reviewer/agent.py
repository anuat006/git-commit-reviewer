"""Root agent: a LangGraph state machine that orchestrates MCP tool calls.

    decide(state) is called after every node and picks the next node from AgentState:

        get_diff -> scan -> diagnose -> gate -> create_issue -> finish
        (any state with `status` set, i.e. failure / clean / declined, goes straight to finish)

`decide` implements the safety rules:
  * diff failed / empty            -> finish (no scan)
  * scan failed                    -> finish (no approval, no issue)
  * no findings (clean commit)     -> finish (no approval prompt)
  * human says no                  -> finish (no issue)
  * issue call failed / unverified -> finish as failed (never claim success)
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any, Optional, TypedDict

from langgraph.graph import END, StateGraph

from .approval import Approval, ApprovalGate
from .audit import AuditLog
from .llm import LLMError
from .logsetup import fmt_args
from .mcp_client import McpClient, McpUnavailable, ToolCallError, ToolTimeout
from .redact import scrub
from .issue_template import IssueReport
from .schemas import (REQUIRED_TOOLS, SEVERITY_ORDER, TOOL_GET_DIFF, TOOL_ISSUE, TOOL_SCAN,
                      Diagnosis, Finding, ReviewOutcome, ReviewRequest, ToolResult)

log = logging.getLogger("agent")
TIMEOUT = {TOOL_GET_DIFF: 30.0, TOOL_SCAN: 30.0, TOOL_ISSUE: 45.0}
RETRIES = {TOOL_GET_DIFF: 1, TOOL_SCAN: 1, TOOL_ISSUE: 0}  # never auto-retry issue creation

_RISK = {
    "password": "A hard-coded password lets anyone with repository access authenticate to the target system.",
    "api_token": "An exposed API token allows unauthorised use of the linked service until it is revoked.",
    "unsafe_config": "Unsafe configuration weakens security controls (e.g. debug mode, disabled TLS verification).",
}
_RECO = {
    "password": "Remove it from history, rotate the credential, load it from a secret manager or env var.",
    "api_token": "Revoke and rotate the token, purge it from history, load it from a secret manager.",
    "unsafe_config": "Replace with a secure default and review the deployment configuration.",
}



class AgentState(TypedDict, total=False):
    request: ReviewRequest
    diff_result: Optional[dict]      # get_commit_diff `data`; input of scan_commit
    scan_result: Optional[ToolResult]
    changed_files: list[str]
    diagnosis: Optional[Diagnosis]
    approval: Optional[Approval]
    issue_number: Optional[int]
    issue_url: Optional[str]
    status: str          # clean | issue_created | declined | failed
    message: str


class RootAgent:
    def __init__(self, client: McpClient, gate: ApprovalGate, audit: AuditLog, llm=None):
        self.client, self.gate, self.audit, self.llm = client, gate, audit, llm
        self.graph = self._build_graph()

    # ------------------------------------------------------------- graph --
    def _build_graph(self):
        g = StateGraph(AgentState)
        for name, fn in [("get_diff", self.n_get_diff), ("scan", self.n_scan),
                         ("diagnose", self.n_diagnose), ("gate", self.n_gate),
                         ("create_issue", self.n_create_issue), ("finish", self.n_finish)]:
            g.add_node(name, fn)
        targets = {n: n for n in ("get_diff", "scan", "diagnose", "gate", "create_issue", "finish")}
        g.set_conditional_entry_point(self.decide, targets)
        for node in ("get_diff", "scan", "diagnose", "gate", "create_issue"):
            g.add_conditional_edges(node, self.decide, targets)
        g.add_edge("finish", END)
        return g.compile()

    def run(self, request: ReviewRequest) -> ReviewOutcome:
        ids = {"repository": request.repository, "commit_id": request.commit_id,
               "github_repo": request.github_repo}
        self.audit.record("alert", reason="review requested", inputs=ids, outcome="received")
        try:
            self._connect()
        except McpUnavailable as exc:
            self.audit.record("final", reason="workflow end", outcome=f"failed: MCP server unavailable: {exc}")
            return ReviewOutcome("failed", request, message=f"MCP server unavailable: {exc}")
        try:
            st = self.graph.invoke({"request": request})
        finally:
            self.client.close()
        approval = st.get("approval")
        return ReviewOutcome(st["status"], request, diagnosis=st.get("diagnosis"),
                             human_decision=approval.decision if approval else None,
                             issue_number=st.get("issue_number"), issue_url=st.get("issue_url"),
                             message=st.get("message", ""))

    # ------------------------------------------------------------- nodes --
    def n_get_diff(self, st: AgentState) -> dict:
        r = st["request"]
        res = self._call(TOOL_GET_DIFF, {"repository": r.repository, "commit_id": r.commit_id},
                         "Need the commit diff and changed-file list before scanning")
        if not res.success or not res.data.get("commit_id"):
            return {"status": "failed",
                    "message": f"Could not obtain commit diff: {res.error or res.summary}"}
        files = list(res.data.get("changed_files") or [])
        if not files:
            return {"status": "clean", "message": "Commit changes no files; nothing to scan."}
        return {"diff_result": res.data, "changed_files": files}

    def n_scan(self, st: AgentState) -> dict:
        res = self._call(TOOL_SCAN, {"diff_result": st["diff_result"]},
                         f"Scan {len(st['changed_files'])} changed file(s) for password/token/unsafe-config rules")
        if not res.success:
            return {"scan_result": res, "status": "failed",
                    "message": f"Scan failed: {res.error or res.summary}. No approval requested."}
        return {"scan_result": res}

    def n_diagnose(self, st: AgentState) -> dict:
        d = self.diagnose(st["scan_result"])
        if d.has_findings and self.llm is not None:
            d = self._explain_with_llm(d)
        self.audit.record("diagnosis", reason="evidence-based diagnosis",
                          outcome=f"severity={d.severity} findings={len(d.findings)} "
                                  f"needs_review={d.needs_review}")
        if not d.has_findings:
            return {"diagnosis": d, "status": "clean",
                    "message": "No security findings. No approval needed."}
        return {"diagnosis": d}

    def n_gate(self, st: AgentState) -> dict:
        r = st["request"]
        ap = self.gate.request(self.summarise(st), r.repository, r.commit_id)
        log.info("human gate: decision=%s", ap.decision)
        self.audit.record("human_gate", tool="approval",
                          reason="Findings require human approval before any external action",
                          outcome="approved" if ap.approved else "declined", human_decision=ap.decision)
        if not ap.approved or not ap.token:
            return {"approval": ap, "status": "declined", "message": "Human declined. No issue created."}
        return {"approval": ap}

    def n_create_issue(self, st: AgentState) -> dict:
        res = self._call(TOOL_ISSUE, self._issue_args(st),
                         "Human approved: create ONE redacted GitHub issue (no auto-retry)")
        if not res.success:
            return {"status": "failed",
                    "message": f"Issue creation failed: {res.error or res.summary}. Not retried."}
        num, url = self._verified_issue(st["request"], res)
        if num is None:
            return {"status": "failed", "message": "Tool reported success but no verifiable issue "
                                                    "number/URL; not claiming the issue exists."}
        return {"status": "issue_created", "issue_number": num, "issue_url": url,
                "message": f"Issue #{num} created: {url}"}

    def n_finish(self, st: AgentState) -> dict:
        ap = st.get("approval")
        log.info("done: %s | %s", st["status"], st.get("message", ""))
        self.audit.record("final", reason="workflow end",
                          outcome=f"{st['status']}: {st.get('message', '')}",
                          human_decision=ap.decision if ap else None)
        return {}

    # ------------------------------------------------------------ routing --
    def decide(self, st: AgentState) -> str:
        """Look at the whole AgentState and choose the next node."""
        if st.get("status"):                        # failed / clean / declined / issue_created
            nxt = "finish"
        elif st.get("diff_result") is None:
            nxt = "get_diff"
        elif st.get("scan_result") is None:
            nxt = "scan"
        elif st.get("diagnosis") is None:
            nxt = "diagnose"
        elif st.get("approval") is None:
            nxt = "gate"
        else:                                       # approved (a decline would have set status)
            nxt = "create_issue"
        log.info("decide: next step = %s", nxt)
        self.audit.record("decision", tool=nxt, reason="route from AgentState", outcome=f"next={nxt}")
        return nxt

    # ------------------------------------------------------------ MCP calls --
    def _connect(self) -> None:
        """Start the server and discover its tools; all three must be present."""
        try:
            self.client.start()
            found = set(self.client.list_tools())
            missing = [t for t in REQUIRED_TOOLS if t not in found]
            if missing:
                raise McpUnavailable(f"missing required tools: {missing}")
        except Exception as exc:
            log.error("MCP server unavailable: %s", exc)
            self.audit.record("mcp_connect", tool="mcp", reason="startup + tool discovery",
                              outcome=f"FAILED - {exc}")
            self.client.close()
            raise McpUnavailable(str(exc)) from exc
        log.info("MCP server started; tools discovered: %s", ", ".join(sorted(found)))
        self.audit.record("mcp_connect", tool="mcp", reason="startup + tool discovery",
                          outcome=f"OK - discovered {sorted(found)}")

    def _call(self, tool: str, args: dict[str, Any], reason: str) -> ToolResult:
        """Call one MCP tool: timeout, bounded retry (never for issue), audit every attempt."""
        if tool == TOOL_ISSUE and not args.get("approval_token"):
            log.warning("x refused %s: no approval token", tool)
            return self._log(tool, args, reason,
                             ToolResult(False, "Refused: no approval token", error="approval_required"))
        err, tries = "", RETRIES.get(tool, 0) + 1
        for attempt in range(tries):
            log.info("-> calling %s  %s  (attempt %d/%d) | %s", tool, fmt_args(args), attempt + 1, tries, reason)
            t0 = time.monotonic()
            try:
                raw = self.client.call_tool(tool, args, TIMEOUT.get(tool, 30.0))
                res = ToolResult.from_dict(raw)
                log.info("<- %s success=%s (%.2fs) | %s%s", tool, res.success, time.monotonic() - t0,
                         res.summary, f" | error={res.error}" if res.error else "")
                return self._log(tool, args, reason, res, attempt=attempt)
            except (ToolTimeout, ToolCallError) as exc:
                err = f"{type(exc).__name__}: {exc}"
                log.warning("<- %s FAILED (%.2fs) %s%s", tool, time.monotonic() - t0, err,
                            "; retrying" if attempt + 1 < tries else "; no retries left")
                self._log(tool, args, reason, ToolResult(False, "transport failure", error=err),
                          attempt=attempt)
        return ToolResult(False, "Tool failed; stopping safely", error=err)

    def _log(self, tool, args, reason, result: ToolResult, **extra) -> ToolResult:
        self.audit.record("tool_call", tool=tool, reason=reason, inputs=args,
                          outcome=f"success={result.success} | {result.summary}"
                                  + (f" | error={result.error}" if result.error else ""), **extra)
        return result

    # ----------------------------------------------------------- diagnosis --
    def diagnose(self, scan: ToolResult) -> Diagnosis:
        raw = scan.data.get("findings") or []
        findings = [Finding.from_dict(f) for f in raw if isinstance(f, dict)]
        for f in findings:                       # defensive re-redaction
            f.evidence = scrub(f.evidence)
            f.recommendation = f.recommendation or _RECO.get(f.rule, "Review manually.")
        if not findings:
            return Diagnosis([], "NONE", "No risk detected by supported rules.", "", "high", False)
        top = max(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 0))
        # Evidence wins over guesses: any low-confidence item -> "Needs review".
        needs_review = any(f.confidence == "low" for f in findings)
        order = {"low": 0, "medium": 1, "high": 2}
        conf = min((f.confidence for f in findings), key=lambda c: order.get(c, 0))
        rules = sorted({f.rule for f in findings})
        return Diagnosis(findings, top.severity,
                         " ".join(_RISK.get(r, "Potential security issue.") for r in rules),
                         " ".join(dict.fromkeys(f.recommendation for f in findings)),
                         conf, needs_review)

    _LLM_SYSTEM = (
        "You are a security reviewer. You receive REDACTED findings from a scanner. "
        "Use ONLY the evidence given; never invent findings, secrets or files. "
        'Reply with a JSON object: {"risk": "<1-3 sentences>", "recommendation": '
        '"<1-3 sentences>", "confidence": "high|medium|low", "needs_review": true|false}. '
        "Set needs_review=true if the evidence is ambiguous (e.g. may be a placeholder or test value)."
    )

    def _llm_label(self) -> str:
        return getattr(self.llm, "label", None) or f"ollama:{getattr(self.llm, 'model', '?')}"

    def _explain_with_llm(self, d: Diagnosis) -> Diagnosis:
        """Model writes risk/recommendation and may flag 'Needs review'. Guardrails: it can
        not change severity, add/remove findings, or lower the scanner's confidence."""
        lines = [f"- rule={f.rule} file={f.file}:{f.line} severity={f.severity} "
                 f"scanner_confidence={f.confidence} evidence={f.evidence}" for f in d.findings]
        try:
            out = self.llm.chat_json(self._LLM_SYSTEM, "Findings:\n" + "\n".join(lines))
            risk, reco = str(out.get("risk", "")).strip(), str(out.get("recommendation", "")).strip()
            if not risk or not reco:
                raise LLMError("model answer missing risk/recommendation")
        except LLMError as exc:
            log.warning("llm: %s call failed (%s); using rule-based text", self._llm_label(), exc)
            self.audit.record("llm_call", tool=self._llm_label(),
                              reason="explain findings", outcome=f"FAILED - {exc}; using rule-based text")
            return d
        order = {"low": 0, "medium": 1, "high": 2}
        m_conf = str(out.get("confidence", "")).lower()
        if m_conf in order and order[m_conf] < order[d.confidence]:
            d.confidence = m_conf                       # model may only LOWER confidence
        d.needs_review = d.needs_review or out.get("needs_review") is True
        d.risk, d.recommendation = scrub(risk)[:600], scrub(reco)[:600]
        log.info("llm: %s explained findings (confidence=%s needs_review=%s)",
                 self._llm_label(), d.confidence, d.needs_review)
        self.audit.record("llm_call", tool=self._llm_label(),
                          reason="explain findings",
                          outcome=f"OK - confidence={d.confidence} needs_review={d.needs_review}")
        return d

    def summarise(self, st: AgentState) -> str:
        d, r = st["diagnosis"], st["request"]
        lines = [f"\n=== Security findings in {r.repository}@{r.commit_id} ===",
                 f"Severity: {d.severity}   Confidence: {d.confidence}"
                 + ("   [NEEDS REVIEW]" if d.needs_review else "")]
        for f in d.findings:
            lines.append(f"  - [{f.severity}] {f.rule}\n      file: {f.file}\n      line: {f.line}\n"
                         f"      evidence: {f.evidence}")
        lines += [f"Risk: {d.risk}", f"Recommendation: {d.recommendation}",
                  f"Target: {r.github_repo} (redacted evidence only)"]
        return "\n".join(lines)

    # --------------------------------------------------------------- issue --
    def _issue_args(self, st: AgentState) -> dict[str, Any]:
        r = st["request"]
        report = IssueReport.from_diagnosis(r, st["diagnosis"])     # one uniform template
        return {"github_repo": r.github_repo, "repository": r.repository, "commit_id": r.commit_id,
                "title": report.title, "body": report.render_body(),
                "approval_token": st["approval"].token}

    @staticmethod
    def _verified_issue(request: ReviewRequest, res: ToolResult) -> tuple[Optional[int], Optional[str]]:
        data = res.data
        num, url = data.get("issue_number"), data.get("issue_url")
        pat = rf"^https://github\.com/{re.escape(request.github_repo)}/issues/(\d+)$"
        m = re.match(pat, url or "", re.I)
        if isinstance(num, int) and m and int(m.group(1)) == num:
            return num, url
        return None, None

