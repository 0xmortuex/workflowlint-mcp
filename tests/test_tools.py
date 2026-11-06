"""The tools on real files: overview, permissions, graph, triggers, reusable-workflow checks, fix previews
(applied with a real `git apply` and re-linted)."""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone

import pytest

from workflowlint_mcp import server
from workflowlint_mcp.model import load_doc
from workflowlint_mcp.rules import lint_doc
from workflowlint_mcp.triggers import explain

from conftest import write


def repo(tmp_path, files: dict[str, str]):
    for rel, text in files.items():
        write(str(tmp_path / rel), text)
    server.configure(str(tmp_path))
    return tmp_path


WF = ".github/workflows/"


def test_overview_lists_secret_names_only_and_pin_state(tmp_path):
    repo(tmp_path, {WF + "a.yml": (
        "name: A\non: [push]\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-24.04\n"
        "    environment: prod\n    steps:\n      - uses: actions/checkout@v4\n"
        "      - uses: foo/bar@0123456789abcdef0123456789abcdef01234567 # v2.1.0\n"
        "      - run: deploy\n        env:\n          K: ${{ secrets.DEPLOY_KEY }}\n"
        "          L: hunter2-literal-value\n")})
    out = server.workflows_overview(".")
    assert "DEPLOY_KEY" in out and "hunter2" not in out
    assert "actions/checkout@v4 (NOT pinned to a SHA)" in out
    assert "pinned SHA, v2" in out
    assert "environment: prod" in out and "triggers: push" in out


def test_overview_reports_invalid_yaml_with_line(tmp_path):
    repo(tmp_path, {WF + "bad.yml": "on: push\njobs: [oops\n", WF + "ok.yml": "on: push\njobs: {}\n"})
    out = server.workflows_overview(".")
    assert "INVALID YAML at line 3" in out and "ok.yml" in out


def test_permissions_review(tmp_path):
    repo(tmp_path, {WF + "p.yml": (
        "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n"
        "      - uses: actions/checkout@v4\n      - run: make\n"
        "  rel:\n    runs-on: ubuntu-24.04\n    permissions:\n      contents: read\n    steps:\n"
        "      - run: gh release create v1\n      - run: git push\n")})
    out = server.permissions_review(".")
    assert "job a" in out and "possibly more than needed" in out
    assert "least-privilege suggestion" in out and "contents: read" in out
    assert "would FAIL: needs contents: write" in out


def test_permissions_review_without_declaration(tmp_path):
    repo(tmp_path, {WF + "p.yml": "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo\n"})
    out = server.permissions_review(".")
    assert "repository/organization default" in out and "permissions: {}" in out


def test_job_graph_waves_critical_path_and_mermaid(tmp_path):
    repo(tmp_path, {WF + "g.yml": (
        "on: push\njobs:\n  lint:\n    runs-on: x\n    timeout-minutes: 5\n    steps: [{run: a}]\n"
        "  test:\n    runs-on: x\n    timeout-minutes: 20\n    strategy:\n      matrix:\n        v: [1, 2, 3]\n"
        "    steps: [{run: a}]\n"
        "  build:\n    needs: [lint, test]\n    runs-on: x\n    timeout-minutes: 10\n    steps: [{run: a}]\n"
        "  ship:\n    needs: build\n    runs-on: x\n    steps: [{run: a}]\n")})
    out = server.job_graph(".")
    assert "wave 1: lint, test" in out and "wave 2: build" in out and "wave 3: ship" in out
    assert "test x3 matrix legs" in out
    assert "Critical path (3 job(s) deep): test -> build -> ship" in out
    assert "390 min via test -> build -> ship" in out  # 20 + 10 + 360 (ship has no timeout)
    assert "graph LR" in out and 'test["test"] --> build["build"]' in out
    assert "Maximum parallelism: 2" in out


def test_job_graph_reports_cycles(tmp_path):
    repo(tmp_path, {WF + "g.yml": (
        "on: push\njobs:\n  a:\n    needs: b\n    runs-on: x\n    steps: [{run: a}]\n"
        "  b:\n    needs: a\n    runs-on: x\n    steps: [{run: a}]\n")})
    assert "cycle" in server.job_graph(".")


def test_explain_triggers_text(tmp_path):
    repo(tmp_path, {WF + "t.yml": (
        "name: T\non:\n  push:\n    branches: [main, 'release/**']\n    paths: ['src/**']\n"
        "  pull_request:\n    types: [opened]\n  schedule:\n    - cron: '17 3 * * 1'\n    - cron: '0 0 13 * 5'\n"
        "  workflow_dispatch:\n    inputs:\n      level:\n        type: choice\n        required: true\n"
        "jobs: {}\n")})
    out = server.explain_triggers(WF + "t.yml")
    assert "branches matching main, release/**" in out and "when changed files match src/**" in out
    assert "pull request is opened" in out and "read-only" in out
    assert "At 03:17, on Monday (UTC)" in out
    assert "day-of-month 13 OR on Friday" in out
    assert out.count("next runs:") == 2
    assert "default branch" in out and "60 days" in out
    assert "input level: choice, required" in out


def test_explain_triggers_fixed_clock():
    doc = load_doc("w.yml", "on:\n  schedule:\n    - cron: '*/30 8 1 * *'\njobs: {}\n")
    out = explain(doc, datetime(2026, 2, 26, 13, 20, tzinfo=timezone.utc))
    assert "Sun 2026-03-01 08:00 UTC; Sun 2026-03-01 08:30 UTC; Wed 2026-04-01 08:00 UTC" in out


def test_explain_push_with_only_tags_filter():
    doc = load_doc("w.yml", "on:\n  push:\n    tags: ['v*']\njobs: {}\n")
    assert "branch pushes do NOT trigger" in explain(doc, datetime.now(timezone.utc))


# ---- reusable workflow contract (GHA1022) -------------------------------------------------------------

CALLEE = ("on:\n  workflow_call:\n    inputs:\n      target:\n        type: string\n        required: true\n"
          "      mode:\n        type: string\n        default: fast\n    secrets:\n      key:\n        required: true\n"
          "      opt:\n        required: false\njobs:\n  b:\n    runs-on: x\n    steps: [{run: a}]\n")


def caller(body: str) -> str:
    return "on: push\njobs:\n  c:\n" + body


@pytest.mark.parametrize("body,fragment,line", [
    ("    uses: ./.github/workflows/callee.yml\n    secrets: {key: x}\n", "required input `target`", 3),
    ("    uses: ./.github/workflows/callee.yml\n    with:\n      target: a\n      tgt: b\n    secrets: {key: x}\n",
     "input `tgt` is not declared", 7),
    ("    uses: ./.github/workflows/callee.yml\n    with: {target: a}\n", "required secret `key`", 3),
    ("    uses: ./.github/workflows/callee.yml\n    with: {target: a}\n    secrets:\n      key: x\n      other: y\n",
     "secret `other` is not declared", 8),
    ("    uses: ./.github/workflows/missing.yml\n", "does not exist", 4),
    ("    uses: ./.github/workflows/plain.yml\n", "no `workflow_call` trigger", 4),
])
def test_reusable_mismatch(tmp_path, body, fragment, line):
    repo(tmp_path, {WF + "callee.yml": CALLEE, WF + "plain.yml": "on: push\njobs: {}\n", WF + "caller.yml": caller(body)})
    out = server.lint_workflows(WF + "caller.yml")
    hits = [ln for ln in out.splitlines() if "[GHA1022]" in ln]
    assert len(hits) == 1 and fragment in hits[0], out
    assert f"caller.yml:{line} [GHA1022]" in hits[0]


def test_reusable_match_and_inherit_are_clean(tmp_path):
    repo(tmp_path, {WF + "callee.yml": CALLEE, WF + "ok.yml": caller(
        "    uses: ./.github/workflows/callee.yml\n    with: {target: a, mode: slow}\n    secrets: {key: x}\n"),
        WF + "inh.yml": caller("    uses: ./.github/workflows/callee.yml\n    with: {target: a}\n    secrets: inherit\n")})
    for f in ("ok.yml", "inh.yml"):
        assert "GHA1022" not in server.lint_workflows(WF + f)


# ---- fix_preview -------------------------------------------------------------------------------------


def apply_diff(tmp_path, rel: str, preview: str) -> str:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    start = preview.index("--- a/")
    end = preview.index("\n\nVerified")
    patch = tmp_path / "fix.patch"
    patch.write_bytes((preview[start:end] + "\n").encode("utf-8"))
    proc = subprocess.run(["git", "apply", "--unsafe-paths", "fix.patch"], cwd=tmp_path, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    with open(tmp_path / rel, encoding="utf-8", newline="") as fh:
        return fh.read()


INJECT = ("name: x\non: issues\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n"
          "      - run: |\n          echo \"Title: ${{ github.event.issue.title }}\"\n"
          "          echo ${{ github.event.issue.body }} and ${{ github.event.issue.title }}\n"
          "          echo \"::set-output name=n::1\"\n")


def test_fix_preview_moves_injection_into_env_and_patch_applies(tmp_path):
    repo(tmp_path, {WF + "i.yml": INJECT})
    out = server.fix_preview(WF + "i.yml")
    assert "ISSUE_TITLE: ${{ github.event.issue.title }}" in out and "ISSUE_BODY: ${{ github.event.issue.body }}" in out
    assert out.count("ISSUE_TITLE: ${{") == 1  # two uses, one variable
    with open(tmp_path / WF / "i.yml", encoding="utf-8") as fh:
        assert fh.read() == INJECT  # the preview never wrote the file
    patched = apply_diff(tmp_path, WF + "i.yml", out)
    assert 'echo "Title: ${ISSUE_TITLE}"' in patched
    assert 'echo "${ISSUE_BODY}" and "${ISSUE_TITLE}"' in patched
    assert 'echo "n=1" >> "$GITHUB_OUTPUT"' in patched
    doc = load_doc(WF + "i.yml", patched)
    assert doc.error is None
    rules = {f.rule for f in lint_doc(doc)}
    assert "GHA1003" not in rules and "GHA1011" not in rules
    assert "fewer GHA1003" in out and "no new findings introduced" in out


def test_fix_preview_adds_read_only_permissions(tmp_path):
    text = ("name: x\non: push\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n"
            "      - uses: actions/checkout@v4\n      - run: make\n")
    repo(tmp_path, {WF + "p.yml": text})
    out = server.fix_preview(WF + "p.yml")
    assert "+permissions:" in out and "+  contents: read" in out
    patched = apply_diff(tmp_path, WF + "p.yml", out)
    assert "GHA1004" not in {f.rule for f in lint_doc(load_doc(WF + "p.yml", patched))}


def test_fix_preview_refuses_permissions_when_a_job_may_need_write(tmp_path):
    text = ("on: push\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n"
            "      - run: git push\n")
    repo(tmp_path, {WF + "p.yml": text})
    out = server.fix_preview(WF + "p.yml")
    assert "no safe automatic fix applies" in out and "may need more than read access" in out


def test_fix_preview_skips_single_quoted_and_lists_manual_work(tmp_path):
    text = ("on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n"
            "      - run: echo '${{ github.event.issue.title }}'\n")
    repo(tmp_path, {WF + "q.yml": text})
    out = server.fix_preview(WF + "q.yml")
    assert "no safe automatic fix applies" in out and "single quotes" in out


def test_fix_preview_preserves_crlf_and_reuses_existing_env(tmp_path):
    text = ("on: issues\r\npermissions: {}\r\njobs:\r\n  j:\r\n    runs-on: ubuntu-24.04\r\n    timeout-minutes: 5\r\n"
            "    steps:\r\n      - run: echo ${{ github.event.issue.title }}\r\n        env:\r\n          A: b\r\n")
    repo(tmp_path, {WF + "c.yml": text})
    out = server.fix_preview(WF + "c.yml")
    patched = apply_diff(tmp_path, WF + "c.yml", out)
    assert "\r\n" in patched and "\n" not in patched.replace("\r\n", "")
    assert "ISSUE_TITLE: ${{ github.event.issue.title }}" in patched
    assert "GHA1003" not in {f.rule for f in lint_doc(load_doc("c.yml", patched))}


def test_fix_preview_pwsh_uses_env_syntax(tmp_path):
    text = ("on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: windows-2022\n    timeout-minutes: 5\n    steps:\n"
            "      - run: Write-Host \"${{ github.event.issue.title }}\"\n")
    repo(tmp_path, {WF + "w.yml": text})
    patched = apply_diff(tmp_path, WF + "w.yml", server.fix_preview(WF + "w.yml"))
    assert 'Write-Host "${env:ISSUE_TITLE}"' in patched


def test_fix_preview_on_clean_file(tmp_path):
    repo(tmp_path, {WF + "c.yml": "on: push\npermissions: {}\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: a\n"})
    assert "no safe automatic fix applies" in server.fix_preview(WF + "c.yml")


def test_fix_preview_invalid_yaml_is_an_error(tmp_path):
    from mcp.server.mcpserver.exceptions import ToolError  # noqa: F401

    repo(tmp_path, {WF + "bad.yml": "on: [\n"})
    with pytest.raises(Exception, match="not valid YAML"):
        server.fix_preview(WF + "bad.yml")


def test_pin_plan_offline_lists_everything_needing_a_pin(tmp_path):
    repo(tmp_path, {WF + "a.yml": (
        "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n"
        "      - uses: foo/bar@main\n      - uses: foo/bar@main\n"
        "      - uses: ok/ok@0123456789abcdef0123456789abcdef01234567\n      - uses: ./local\n"
        "      - uses: docker://alpine@sha256:abc\n")})
    out = server.pin_actions_plan(".")
    assert "3 reference(s) to 2 distinct action version(s)" in out
    assert "foo/bar@main  [error, branch]" in out and "a.yml:7" in out and "a.yml:8" in out
    assert "git ls-remote https://github.com/foo/bar" in out
    assert "ok/ok" not in out and "./local" not in out
    assert "api.github.com" not in out  # offline: nothing contacted
