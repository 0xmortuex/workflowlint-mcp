"""Hostile inputs: path traversal, symlinks, huge and pathological files, alias bombs, secrets in outputs."""

from __future__ import annotations

import os
import time

import pytest
from mcp.server.mcpserver.exceptions import ToolError  # noqa: F401

from workflowlint_mcp import server
from workflowlint_mcp.errors import UserError
from workflowlint_mcp.graph import render as render_graph
from workflowlint_mcp.model import load_doc
from workflowlint_mcp.rules import lint_doc
from workflowlint_mcp.files import MAX_BYTES, MAX_LINES, Sandbox, real_path

from conftest import write

WF = ".github/workflows/"
SIMPLE = "on: push\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n"

ALL_TOOLS = (server.workflows_overview, server.lint_workflows, server.explain_triggers, server.permissions_review,
             server.job_graph, server.pin_actions_plan, server.fix_preview)


def test_traversal_and_absolute_paths_outside_are_refused(tmp_path):
    root = tmp_path / "proj"
    write(str(root / WF / "a.yml"), SIMPLE)
    write(str(tmp_path / "outside.yml"), SIMPLE)
    write(str(tmp_path / "proj-evil" / "x.yml"), SIMPLE)
    server.configure(str(root))
    for bad in ("../outside.yml", str(tmp_path / "outside.yml"), "../proj-evil/x.yml",
                str(tmp_path / "proj-evil" / "x.yml"), "..", "/", ".github/../../outside.yml"):
        for fn in ALL_TOOLS:
            with pytest.raises(UserError, match="outside the directory|Not found|No workflow files"):
                fn(bad)


def test_nul_and_empty_paths(tmp_path):
    server.configure(str(tmp_path))
    for bad in ("", "a\x00b"):
        with pytest.raises(UserError, match="empty or contains a NUL"):
            server.lint_workflows(bad)


def test_missing_and_non_workflow_paths_have_actionable_errors(tmp_path):
    write(str(tmp_path / "notes.txt"), "hello")
    (tmp_path / "empty").mkdir()
    server.configure(str(tmp_path))
    with pytest.raises(UserError, match="Not found"):
        server.lint_workflows("nope.yml")
    with pytest.raises(UserError, match="No workflow files found"):
        server.lint_workflows("empty")


def test_symlink_escaping_the_sandbox_is_refused(tmp_path):
    root = tmp_path / "proj"
    write(str(root / WF / "ok.yml"), SIMPLE)
    write(str(tmp_path / "secret.yml"), SIMPLE)
    link = root / WF / "link.yml"
    try:
        os.symlink(str(tmp_path / "secret.yml"), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symlinks (Windows without developer mode)")
    server.configure(str(root))
    with pytest.raises(UserError, match="outside the directory"):
        server.lint_workflows(".")
    with pytest.raises(UserError, match="outside the directory"):
        server.lint_workflows(WF + "link.yml")


def test_huge_file_and_too_many_lines_are_refused(tmp_path):
    write(str(tmp_path / WF / "big.yml"), "# " + "x" * (MAX_BYTES + 10) + "\n")
    write(str(tmp_path / WF / "lines.yml"), "a: 1\n" * (MAX_LINES + 5))
    server.configure(str(tmp_path))
    with pytest.raises(UserError, match="limit is"):
        server.lint_workflows(WF + "big.yml")
    with pytest.raises(UserError, match="more than"):
        server.lint_workflows(WF + "lines.yml")


def test_not_utf8_is_refused(tmp_path):
    with open(tmp_path / "w.yml", "wb") as fh:
        fh.write(b"on: push\n# \xff\xfe\n")
    server.configure(str(tmp_path))
    with pytest.raises(UserError, match="not valid UTF-8"):
        server.lint_workflows("w.yml")


def test_hundred_thousand_character_path(tmp_path):
    server.configure(str(tmp_path))
    long = "a" * 100_000
    for fn in ALL_TOOLS:
        with pytest.raises((UserError, OSError)) as ei:
            fn(long)
        assert not isinstance(ei.value, ValueError)
    with pytest.raises(UserError):
        Sandbox(long)
    try:
        real_path(long)  # newer Pythons just return the path; 3.10 on Windows must raise UserError, not ValueError
    except UserError:
        pass


def timed(fn, *args, limit=30.0):
    t = time.perf_counter()
    out = fn(*args)
    assert time.perf_counter() - t < limit, f"{fn.__name__} took {time.perf_counter() - t:.1f}s"
    return out


def run_block(line: str, n_lines: int = 1) -> str:
    body = "".join("          " + line + "\n" for _ in range(n_lines))
    return ("on: push\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n"
            "      - run: |\n" + body)


@pytest.mark.parametrize("name,line,n", [
    ("repeated_curl", "curl " * 20_000, 5),
    ("repeated_pipes", "curl x | " * 5_000, 5),
    ("repeated_expr_open", "${{ " * 20_000, 5),
    ("repeated_quotes", "${{ '" * 20_000, 5),
    ("repeated_brackets", "${{ a[" * 20_000 + "}}", 5),
    ("repeated_dots", "${{ " + "a." * 20_000 + " }}", 5),
    ("repeated_echo_secret", "echo ${{ secrets.X }} " * 3_000, 5),
    ("repeated_set_output", "echo ::set-output " * 5_000, 5),
    ("repeated_substitution", "bash -c $(curl " * 5_000, 5),
    ("repeated_token_prefix", "ghp_" * 20_000, 5),
    ("repeated_eyJ", "eyJ" * 20_000, 5),
    ("many_short_lines", "echo ${{ github.event.issue.title }}", 15_000),
])
def test_pathological_lines_finish_quickly(tmp_path, name, line, n):
    text = run_block(line, n)
    write(str(tmp_path / WF / "p.yml"), text)
    server.configure(str(tmp_path))
    for fn in (server.lint_workflows, server.fix_preview, server.permissions_review, server.workflows_overview):
        out = timed(fn, WF + "p.yml")
        assert isinstance(out, str)


def test_alias_bomb_is_reported_as_invalid_yaml_quickly(tmp_path):
    levels = ["l0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 14):
        levels.append(f"l{i}: &a{i} [{', '.join([f'*a{i - 1}'] * 10)}]")
    write(str(tmp_path / WF / "bomb.yml"), "on: push\n" + "\n".join(levels) + "\njobs: {}\n")
    server.configure(str(tmp_path))
    out = timed(server.lint_workflows, WF + "bomb.yml", limit=20)
    assert "[GHA1000]" in out and "alias bomb" in out


def test_big_alias_of_a_big_block_scalar_is_bounded(tmp_path):
    block = "".join("          echo line\n" for _ in range(4000))
    aliases = "".join("      - *s\n" for _ in range(9_000))
    text = ("on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - &s\n        run: |\n" + block + aliases)
    write(str(tmp_path / WF / "bigalias.yml"), text)
    server.configure(str(tmp_path))
    out = timed(server.lint_workflows, WF + "bigalias.yml", limit=30)
    assert "[GHA1000]" in out and "alias bomb" in out


def test_deeply_nested_yaml(tmp_path):
    write(str(tmp_path / WF / "deep.yml"), "on: push\nx: " + "[" * 5000 + "]" * 5000 + "\njobs: {}\n")
    server.configure(str(tmp_path))
    assert "[GHA1000]" in timed(server.lint_workflows, WF + "deep.yml")


def test_very_long_needs_chain_does_not_blow_the_stack(tmp_path):
    n = 3000
    jobs = "".join(f"  j{i}:\n    runs-on: x\n" + (f"    needs: j{i - 1}\n" if i else "") + "    steps: [{run: a}]\n"
                   for i in range(n))
    write(str(tmp_path / WF / "chain.yml"), "on: push\njobs:\n" + jobs)
    server.configure(str(tmp_path))
    out = timed(server.lint_workflows, WF + "chain.yml")
    assert "GHA1016" not in out
    doc = load_doc(WF + "chain.yml", open(tmp_path / WF / "chain.yml", encoding="utf-8").read())
    graph = timed(render_graph, doc)
    assert f"Critical path ({n} job(s) deep)" in graph
    assert timed(server.job_graph, WF + "chain.yml").startswith("== ")


def test_many_checkouts_in_one_job(tmp_path):
    steps = "".join("      - uses: actions/checkout@v4\n" for _ in range(4000)) + "      - uses: foo/bar@v1\n"
    write(str(tmp_path / WF / "co.yml"), "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n" + steps)
    server.configure(str(tmp_path))
    timed(server.lint_workflows, WF + "co.yml", limit=30)


def test_many_unknown_needs(tmp_path):
    jobs = "".join(f"  j{i}:\n    runs-on: x\n    needs: nope{i}\n    steps: [{{run: a}}]\n" for i in range(3000))
    write(str(tmp_path / WF / "needs.yml"), "on: push\njobs:\n" + jobs)
    server.configure(str(tmp_path))
    doc = load_doc(WF + "needs.yml", open(tmp_path / WF / "needs.yml", encoding="utf-8").read())
    found = timed(lint_doc, doc, None, frozenset(), limit=30)
    assert sum(1 for f in found if f.rule == "GHA1015") == 3000
    assert len(timed(server.lint_workflows, WF + "needs.yml")) < 70_000


# ---- secrets never appear in output ------------------------------------------------------------------

FAKE_VALUES = ["hunter2-FAKE-pw-value", "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE1234", "AKIAFAKEFAKEFAKE1234",
               "s3cr3t-in-url-FAKE", "sk-FAKEFAKEFAKEFAKEFAKEFAKE1234"]

PLANTED = f"""on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      DB_PASSWORD: {FAKE_VALUES[0]}
      API_TOKEN: {FAKE_VALUES[1]}
      AWS_ACCESS_KEY_ID: {FAKE_VALUES[2]}
    steps:
      - uses: actions/checkout@v4
      - run: git clone https://deploy:{FAKE_VALUES[3]}@example.test/repo.git
      - run: echo "${{{{ github.event.issue.title }}}}"
        env:
          password: {FAKE_VALUES[0]}
      - run: |
          echo {FAKE_VALUES[4]}
          curl -H "Authorization: Bearer {FAKE_VALUES[1]}" ${{{{ secrets.REAL_NAME }}}}
"""


def test_planted_secret_values_never_appear_in_any_tool_output(tmp_path):
    write(str(tmp_path / WF / "s.yml"), PLANTED)
    server.configure(str(tmp_path))
    outs = []
    for fn in (server.workflows_overview, server.lint_workflows, server.permissions_review, server.job_graph,
               server.pin_actions_plan, server.fix_preview):
        outs.append(fn(WF + "s.yml"))
    outs.append(server.explain_triggers(WF + "s.yml"))
    blob = "\n".join(outs)
    for v in FAKE_VALUES:
        assert v not in blob, v
    assert "REAL_NAME" in blob  # names are shown, values never
