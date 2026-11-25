#!/usr/bin/env python3
"""Build a local demo git repo for testing the security commit reviewer.

    python scripts/make_demo_repo.py [--dest demo] [--force]

All credentials below are FABRICATED (valid-looking format, not issued by any service).
Keep this repo LOCAL: GitHub push protection may block pushing secret-shaped strings.
Dates/authors are fixed so commit SHAs are identical on every build.
Writes <dest>_expected.json next to the repo: the commit table with the expected result.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

FAKE_AWS_KEY = "AKIAZ7XQ4TNLM5RB2KDV"
FAKE_GH_PAT = "ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
FAKE_DB_PASSWORD = "Sup3rS3cret!2024"
FAKE_SVC_PASSWORD = "Tr0ub4dor&3xyz"

# (message, {path: content}, expected status, expected finding rules)
COMMITS = [
    ("Initial project skeleton",
     {"README.md": "# Demo service\n\nSmall demo app used to test the commit reviewer.\n",
      "app.py": 'import os\n\n\ndef greet(name: str) -> str:\n    return f"Hello, {name}!"\n\n\n'
                'def api_url() -> str:\n    return os.environ.get("API_URL", "http://localhost:8000")\n'},
     "clean", []),
    ("Add AWS access key to settings",
     {"settings.py": f'AWS_REGION = "ap-south-1"\nAWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"\n'},
     "issue", ["api_token"]),
    ("Add database password to config",
     {"db_config.py": f'DB_HOST = "db.internal"\nDB_USER = "app"\nDB_PASSWORD = "{FAKE_DB_PASSWORD}"\n'},
     "issue", ["password"]),
    ("Enable debug mode and disable TLS verification",
     {"server_config.py": "DEBUG = True\nVERIFY_SSL = False\nPORT = 8443\n"},
     "issue", ["unsafe_config"]),
    ("Add input validation helper and unit test",
     {"validators.py": 'def is_valid_username(name: str) -> bool:\n    return name.isalnum() and 3 <= len(name) <= 20\n',
      "test_validators.py": 'from validators import is_valid_username\n\n\ndef test_username():\n'
                            '    assert is_valid_username("alice1")\n    assert not is_valid_username("a!")\n'},
     "clean", []),
    ("Add GitHub token to deploy script",
     {"deploy.sh": f'#!/bin/sh\nexport GITHUB_TOKEN="{FAKE_GH_PAT}"\necho "deploying..."\n'},
     "issue", ["api_token"]),
    ("Add payment client settings",
     {"payments.py": f'API_BASE = "https://pay.example.test"\nSERVICE_PASSWORD = "{FAKE_SVC_PASSWORD}"\n'
                     f'AWS_SECRET_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"\nDEBUG = True\n'},
     "issue", ["api_token", "password", "unsafe_config"]),
]


def git(repo: Path, *args: str, env=None) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                         text=True, env=env)
    return out.stdout.strip()


def build(dest: Path, force: bool = False) -> list[dict]:
    if dest.exists() and any(dest.iterdir()):
        if not force:
            sys.exit(f"{dest} already exists and is not empty (use --force to rebuild)")
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(dest)], check=True)
    git(dest, "config", "user.name", "Demo Dev")
    git(dest, "config", "user.email", "demo@example.test")
    git(dest, "config", "commit.gpgsign", "false")
    table = []
    for i, (msg, files, expected, rules) in enumerate(COMMITS):
        for rel, content in files.items():
            (dest / rel).write_text(content, encoding="utf-8", newline="\n")
        git(dest, "add", "-A")
        when = f"2026-01-{i + 1:02d}T10:00:00+00:00"
        env = {**os.environ, "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
        git(dest, "commit", "-q", "-m", msg, env=env)
        table.append({"n": i + 1, "sha": git(dest, "rev-parse", "HEAD"), "message": msg,
                      "expected": expected, "expected_rules": rules})
    return table


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dest", default="demo")
    p.add_argument("--force", action="store_true")
    a = p.parse_args()
    dest = Path(a.dest).resolve()
    table = build(dest, a.force)
    manifest = dest.parent / f"{dest.name}_expected.json"
    manifest.write_text(json.dumps(table, indent=2), encoding="utf-8")
    print(f"Demo repo: {dest}\n")
    print(f"{'#':<3} {'commit':<12} {'expected':<8} {'findings':<40} message")
    for r in table:
        print(f"{r['n']:<3} {r['sha'][:10]:<12} {r['expected']:<8} {','.join(r['expected_rules']) or '-':<40} {r['message']}")
    print(f"\nManifest: {manifest}")


if __name__ == "__main__":
    main()
