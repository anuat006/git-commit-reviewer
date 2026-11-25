# Evidence of the three demo runs

Run on 2026-11-25 against the 7-commit demo repo (fake credentials only, built by `scripts/make_demo_repo.py`).
Each folder holds the console output (`console.txt`), the raw audit trail (`audit_log.jsonl`) and a readable
version of it (`audit_trail.txt`).

| # | Case | Commit | Human answer | Result | Folder |
|---|---|---|---|---|---|
| 1 | Finding found, approved, issue created | `04a72c072a` (AWS-style key) | yes | `issue_created`: [issue #4](https://github.com/anuat006/issue-tracker/issues/4) | `01_issue_created/` |
| 2 | Finding found, declined | `4f68ee26c7` (hardcoded password) | no | `declined`, no issue | `02_declined_by_human/` |
| 3 | Clean commit | `7955777f9e` (initial skeleton) | no prompt | `clean`, no issue | `03_clean_commit/` |

Case 1 also has the issue as GitHub returned it: `issue_4.json` and `issue_4_body.md`.

## What was real and what was not

- **Real:** git, Gitleaks 8.21.2 with the project's `rules.toml`, the MCP server over stdio, the approval gate and
  token check, and the GitHub REST API (issue #4 exists in `anuat006/issue-tracker`).
- **Not exercised: the model step.** The runs were made in an environment where Ollama is not available, so the
  log shows `model gateway: ollama:llama3.1 unavailable ... using rule-based text` and the risk and
  recommendation text is the built-in rule-based text. To capture the model step, run the same commands on the
  machine where Ollama is installed.
- **The approval prompt was answered from standard input** (`echo yes |` or `echo no |`) at the project owner's
  request, so the answer was typed by the operator, not by the program.
- Paths in the logs (`/sessions/.../work/demo`) belong to the machine the runs were made on. The line
  `Log : /tmp/...` in the console output is where the audit file was written; a copy is `audit_log.jsonl`.

## Notes

- An earlier attempt of case 1 created [issue #3](https://github.com/anuat006/issue-tracker/issues/3). Its Evidence
  cell showed a useless fragment (`REDACTED"`), which was fixed in `reviewer_server/scanner.py` before issue #4
  was created. Issue #3 is still open in the tracker and can be closed.
- No secret value appears in any file in this folder; evidence is masked by the scanner and scrubbed again.

## Command used

```
python -m reviewer --repo <path to demo repo> --commit <commit id> --model local
```
(`ISSUE_REPO`, `GITHUB_TOKEN` and the other settings come from `.env`.)
