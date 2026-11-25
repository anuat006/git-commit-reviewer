from reviewer.issue_template import IssueReport
from reviewer.schemas import Diagnosis, Finding, ReviewRequest

F = Finding("password", "config/settings.py", 12, "DB_PASSWORD = \"****\"", "HIGH", "high")
D = Diagnosis([F], "HIGH", "Credential exposed.", "Rotate it.", "high", True)
R = ReviewRequest(r"C:\workspace\gitspace\test\demo-repo\demo", "04a72c072a" + "b" * 30, "o/tracker")


def test_uniform_layout():
    rep = IssueReport.from_diagnosis(R, D)
    body = rep.render_body()
    assert rep.title == "[Security] HIGH finding(s) in demo @ 04a72c072a"
    order = ["**Repository:** `demo`", "**Severity:** HIGH", "**Status:** Needs review", "### Findings", "| Rule | File | Line | Severity | Evidence |",
             "| password | `config/settings.py` | 12 | HIGH |", "### Risk", "### Recommendation",
             "_Evidence is redacted", "<!-- reviewer commit:04a72c072a"]
    pos = [body.index(s) for s in order]
    assert pos == sorted(pos)
    assert "rules:password -->" in body


def test_no_status_line_when_not_flagged_and_secrets_scrubbed():
    d = Diagnosis([Finding("api_token", "a.py", 1, "ghp_" + "A" * 36, "CRITICAL", "high")],
                  "CRITICAL", "r", "x", "high", False)
    body = IssueReport.from_diagnosis(R, d).render_body()
    assert "Needs review" not in body and "A" * 36 not in body


def test_full_commit_sha_survives_scrubbing():
    body = IssueReport.from_diagnosis(R, D).render_body()
    assert R.commit_id in body and "commit:" + R.commit_id in body


def test_pipe_in_evidence_does_not_break_table():
    d = Diagnosis([Finding("password", "a|b.py", 3, 'x = "a|b"', "HIGH", "high")], "HIGH", "r", "x", "high", False)
    row = [l for l in IssueReport.from_diagnosis(R, d).render_body().splitlines() if l.startswith("| password")][0]
    assert row.count("|") - row.count("\\|") == 6
