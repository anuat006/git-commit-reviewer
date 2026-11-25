# [Security] HIGH finding(s) in demo @ 04a72c072a

**Repository:** `demo`  
**Commit:** `04a72c072a`  
**Severity:** HIGH  
**Confidence:** high

### Findings
| Rule | File | Line | Severity | Evidence |
|---|---|---|---|---|
| api_token | `settings.py` | 2 | HIGH | `REDACTED"` |

### Risk
An exposed API token allows unauthorised use of the linked service until it is revoked.

### Recommendation
Revoke and rotate the token, purge it from history, load it from a secret manager.

_Evidence is redacted. Created after explicit human approval._
<!-- reviewer commit:04a72c072a repo:demo rules:api_token -->
