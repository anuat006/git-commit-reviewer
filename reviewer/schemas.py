"""Shared data contracts: the JSON shapes every MCP tool must return."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# The only three tools the root agent knows about (spec: 3-5 narrowly scoped tools).
TOOL_GET_DIFF = "get_commit_diff"
TOOL_SCAN = "scan_commit"
TOOL_ISSUE = "create_security_issue"
REQUIRED_TOOLS = (TOOL_GET_DIFF, TOOL_SCAN, TOOL_ISSUE)

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class ToolResult:
    """Uniform envelope: success, summary, redacted data, error."""
    success: bool
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, raw: Any) -> "ToolResult":
        if not isinstance(raw, dict) or "success" not in raw:
            return cls(False, "Malformed tool result", {}, "malformed_result")
        return cls(
            success=bool(raw.get("success")),
            summary=str(raw.get("summary", "")),
            data=raw.get("data") or {},
            error=raw.get("error"),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Expected item of scan_commit `data["findings"]`. Evidence is always redacted."""
    rule: str            # password | api_token | unsafe_config
    file: str
    line: int
    evidence: str        # redacted
    severity: str        # LOW | MEDIUM | HIGH | CRITICAL
    confidence: str      # high | medium | low
    recommendation: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            rule=str(d.get("rule", "unknown")),
            file=str(d.get("file", "?")),
            line=int(d.get("line", 0) or 0),
            evidence=str(d.get("evidence", "")),
            severity=str(d.get("severity", "MEDIUM")).upper(),
            confidence=str(d.get("confidence", "low")).lower(),
            recommendation=str(d.get("recommendation", "")),
        )


@dataclass
class Diagnosis:
    findings: list[Finding]
    severity: str                 # highest severity, or NONE
    risk: str
    recommendation: str
    confidence: str
    needs_review: bool            # True when evidence is uncertain

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


@dataclass
class ReviewRequest:
    repository: str      # local path, e.g. ./demo
    commit_id: str
    github_repo: str     # owner/name


@dataclass
class ReviewOutcome:
    status: str          # clean | issue_created | declined | stopped | failed
    request: ReviewRequest
    diagnosis: Optional[Diagnosis] = None
    human_decision: Optional[str] = None   # yes | no | None
    issue_number: Optional[int] = None
    issue_url: Optional[str] = None
    message: str = ""
