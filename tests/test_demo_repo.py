"""Dry-run check: demo repo shape + our custom rules.toml patterns against every commit.

Token shapes below are copied from gitleaks' default aws/github-pat rules (approximation);
the real gitleaks scan is still the source of truth.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import make_demo_repo as demo  # noqa: E402

tomllib = pytest.importorskip("tomllib")

TOKEN_SHAPES = [re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}"),
                re.compile(r"ghp_[0-9a-zA-Z]{36}")]


@pytest.fixture(scope="module")
def table(tmp_path_factory):
    return demo.build(tmp_path_factory.mktemp("d") / "demo"), tmp_path_factory


def added_lines(repo, sha):
    out = subprocess.run(["git", "-C", str(repo), "show", "--format=", "--unified=0", sha],
                         capture_output=True, text=True, check=True).stdout
    return [l[1:] for l in out.splitlines() if l.startswith("+") and not l.startswith("+++")]


def test_shape_at_least_5_commits_2_clean():
    assert len(demo.COMMITS) >= 5
    assert sum(1 for c in demo.COMMITS if c[2] == "clean") >= 2
    assert {"api_token", "password", "unsafe_config"} <= {r for c in demo.COMMITS for r in c[3]}


def test_rules_match_expected_findings_per_commit(tmp_path):
    table = demo.build(tmp_path / "demo")
    cfg = tomllib.loads((ROOT / "reviewer_server" / "rules.toml").read_text())
    rules = {r["id"]: re.compile(r["regex"]) for r in cfg["rules"]}
    for row in table:
        lines = added_lines(tmp_path / "demo", row["sha"])
        found = set()
        for line in lines:
            if any(p.search(line) for p in TOKEN_SHAPES):
                found.add("api_token")
            if rules["hardcoded-password"].search(line):
                found.add("password")
            if rules["unsafe-config-debug"].search(line) or rules["unsafe-config-tls-verify-disabled"].search(line):
                found.add("unsafe_config")
        assert found == set(row["expected_rules"]), (row["message"], found)
