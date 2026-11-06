"""Realistic good workflows (matrix CI, OIDC release, Pages, safe dependabot automerge, reusable workflows,
local composite action...) must produce ZERO findings with every rule enabled."""

from __future__ import annotations

import os

import pytest

from workflowlint_mcp.files import Sandbox, discover
from workflowlint_mcp.model import load_doc
from workflowlint_mcp.rules import lint_doc
from workflowlint_mcp import server

from conftest import GOOD_REPO

FILES = sorted(
    os.path.join(dp, f) for dp, _, fs in os.walk(GOOD_REPO) for f in fs if f.endswith((".yml", ".yaml"))
)


def test_corpus_has_fifteen_plus_workflows():
    wfs = [f for f in FILES if f.replace("\\", "/").endswith(tuple(["/workflows/" + os.path.basename(f)]))]
    assert len(wfs) >= 15


@pytest.mark.parametrize("path", FILES, ids=[os.path.basename(os.path.dirname(f)) + "/" + os.path.basename(f) for f in FILES])
def test_good_file_has_no_findings(path):
    sb = Sandbox(GOOD_REPO)
    server.configure(GOOD_REPO)
    real, text = sb.read_text(path)
    doc = load_doc(sb.display(real), text)
    assert doc.error is None
    found = lint_doc(doc, server.make_loader(sb, real))
    assert found == [], "\n".join(f"{f.rule}:{f.line} {f.message}" for f in found)


def test_directory_lint_has_no_findings_and_all_tools_run():
    server.configure(GOOD_REPO)
    out = server.lint_workflows(".")
    assert "0 finding(s)" in out
    assert len(discover(Sandbox(GOOD_REPO), ".")) == len(FILES)
    for fn in (server.workflows_overview, server.permissions_review, server.job_graph):
        assert fn(".")
    assert "Every `uses:` is already pinned" in server.pin_actions_plan(".")
    assert "Nothing to do" in server.pin_actions_plan(".")
    for f in FILES:
        if "/workflows/" in f.replace("\\", "/"):
            assert server.explain_triggers(f)


def test_good_corpus_patterns_are_really_present():
    """Guard against a corpus that passes only because it avoids the interesting constructs."""
    blob = "\n".join(open(f, encoding="utf-8").read() for f in FILES)
    for needle in ("id-token: write", "deploy-pages", "pull_request_target", "workflow_call", "matrix:",
                   "fetch-metadata", "composite", "schedule:", "workflow_run", "environment:"):
        assert needle in blob, needle
