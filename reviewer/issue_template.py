"""The ONE place that defines how a security issue looks, so every issue is uniform."""
from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass, field
from typing import Optional

from .redact import scrub, scrub_keeping
from .schemas import Diagnosis, Finding, ReviewRequest

FOOTER = "_Evidence is redacted. Created after explicit human approval._"


@dataclass
class IssueFinding:
    rule: str
    file: str
    line: int
    severity: str
    evidence: str            # already redacted

    @classmethod
    def from_finding(cls, f: Finding) -> "IssueFinding":
        return cls(f.rule, f.file, f.line, f.severity, f.evidence)

    def render_row(self) -> str:
        cell = lambda s: str(s).replace("|", "\\|").replace("`", "'").replace("\n", " ")
        return (f"| {cell(self.rule)} | `{cell(self.file)}` | {self.line} | {cell(self.severity)} "
                f"| `{cell(self.evidence)}` |")


@dataclass
class IssueReport:
    commit_id: str
    source_repo: str                 # name of the scanned repo (folder name, not the full local path)
    severity: str
    confidence: str
    risk: str
    recommendation: str
    findings: list[IssueFinding] = field(default_factory=list)
    needs_review: bool = False

    @classmethod
    def from_diagnosis(cls, req: ReviewRequest, d: Diagnosis) -> "IssueReport":
        name = ntpath.basename(req.repository.rstrip("/\\")) or req.repository
        return cls(req.commit_id, name, d.severity, d.confidence, d.risk, d.recommendation,
                   [IssueFinding.from_finding(f) for f in d.findings], d.needs_review)

    @property
    def title(self) -> str:
        return f"[Security] {self.severity} finding(s) in {self.source_repo} @ {self.commit_id[:10]}"

    @property
    def marker(self) -> str:
        """Hidden line (invisible on GitHub) so code can later find/dedupe issues for this commit."""
        rules = ",".join(sorted({f.rule for f in self.findings}))
        return f"<!-- reviewer commit:{self.commit_id} repo:{self.source_repo} rules:{rules} -->"

    def render_body(self) -> str:
        meta = [f"**Repository:** `{self.source_repo}`",
                f"**Commit:** `{self.commit_id}`",
                f"**Severity:** {self.severity}",
                f"**Confidence:** {self.confidence}"]
        if self.needs_review:
            meta.append("**Status:** Needs review")
        lines = ["  \n".join(meta), "", "### Findings", "| Rule | File | Line | Severity | Evidence |",
                 "|---|---|---|---|---|", *[f.render_row() for f in self.findings],
                 "", "### Risk", self.risk, "", "### Recommendation", self.recommendation,
                 "", FOOTER, self.marker]
        return scrub_keeping("\n".join(lines), [self.commit_id])   # commit sha is an identifier, not a secret
