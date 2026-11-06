"""YAML 1.1 pitfalls, line numbers, anchors, alias bombs, expression scanning and the injection-context table."""

from __future__ import annotations

import pytest

from workflowlint_mcp.expr import dangerous, find_expressions, tokens
from workflowlint_mcp.model import MAX_NODES, load_doc, parse_yaml, script_lines
from workflowlint_mcp.rules import lint_doc


def test_on_key_is_a_string_not_true():
    doc = load_doc("w.yml", "on:\n  push:\n  pull_request:\njobs: {}\n")
    assert set(doc.events) == {"push", "pull_request"}
    assert doc.on_node is not None


def test_on_forms():
    assert set(load_doc("w.yml", "on: push\njobs: {}\n").events) == {"push"}
    assert set(load_doc("w.yml", "on: [push, pull_request]\njobs: {}\n").events) == {"push", "pull_request"}
    assert set(load_doc("w.yml", "'on':\n  push:\njobs: {}\n").events) == {"push"}


def test_yes_no_on_off_are_strings_and_only_true_false_are_booleans():
    root, _ = parse_yaml("a: yes\nb: no\nc: on\nd: off\ne: true\nf: False\ng: ~\nh: 3.10\ni: '3.10'\nj: 010\n")
    assert root.items["a"].value == "yes" and root.items["b"].value == "no"
    assert root.items["c"].value == "on" and root.items["d"].value == "off"
    assert root.items["e"].value is True and root.items["f"].value is False
    assert root.items["g"].value is None
    assert root.items["h"].value == 3.1 and root.items["h"].text == "3.10"
    assert root.items["i"].value == "3.10"


def test_line_numbers_inside_run_blocks():
    text = ("on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: |\n          first\n\n"
            "          third ${{ github.event.issue.title }}\n          fourth\n      - run: echo\n")
    doc = load_doc("w.yml", text)
    node = doc.jobs[0].steps[0].run_node
    assert node is not None
    sl = script_lines(node, doc.lines)
    assert [(s.line, s.text) for s in sl if s.text] == [(7, "first"), (9, "third ${{ github.event.issue.title }}"),
                                                         (10, "fourth")]
    found = [f for f in lint_doc(doc) if f.rule == "GHA1003"]
    assert [f.line for f in found] == [9]


def test_folded_and_indent_indicator_blocks_keep_source_lines():
    text = "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: >\n          a\n          b ${{ github.head_ref }}\n"
    doc = load_doc("w.yml", text)
    assert [f.line for f in lint_doc(doc) if f.rule == "GHA1003"] == [8]


def test_anchors_aliases_and_merge_keys_resolve():
    text = ("on: push\ndefaults: &d\n  run:\n    shell: bash\njobs:\n  a: &job\n    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 5\n    steps:\n      - run: echo hi\n  b:\n    <<: *job\n    timeout-minutes: 9\n")
    doc = load_doc("w.yml", text)
    assert [j.id for j in doc.jobs] == ["a", "b"]
    b = doc.jobs[1]
    assert b.runs_on is not None and b.runs_on.text == "ubuntu-24.04"
    assert b.timeout is not None and b.timeout.text == "9"  # explicit key wins over the merge
    assert len(b.steps) == 1


def test_alias_bomb_is_refused_quickly():
    levels = ["a: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 12):
        prev = f"*a{i - 1}"
        levels.append(f"l{i}: &a{i} [{', '.join([prev] * 10)}]")
    doc = load_doc("w.yml", "\n".join(levels) + "\n")
    assert doc.error is not None and "alias bomb" in doc.error.message
    assert MAX_NODES < 10 ** 6


def test_deep_nesting_is_refused():
    doc = load_doc("w.yml", "a: " + "[" * 500 + "]" * 500 + "\n")
    assert doc.error is not None


@pytest.mark.parametrize("text,line", [
    ("on: push\njobs:\n  j:\n\trun: x\n", 4),
    ("on: push\njobs: [oops\n", 3),
    ("on: push\njobs:\n  j: {a: b\n", 4),
    ("a: b: c\n", 1),
])
def test_invalid_yaml_reports_a_line_instead_of_raising(text, line):
    doc = load_doc("w.yml", text)
    assert doc.error is not None
    assert doc.error.line == line
    findings = lint_doc(doc)
    assert [(f.rule, f.line) for f in findings] == [("GHA1000", line)]


def test_empty_and_non_mapping_files():
    assert load_doc("w.yml", "").error is not None
    assert load_doc("w.yml", "- a\n- b\n").error is not None


def test_crlf_and_utf8_bom_files(tmp_path):
    text = "on: push\r\njobs:\r\n  j:\r\n    runs-on: ubuntu-24.04\r\n    steps:\r\n      - run: |\r\n          echo ${{ github.head_ref }}\r\n"
    doc = load_doc("w.yml", text)
    assert [f.line for f in lint_doc(doc) if f.rule == "GHA1003"] == [7]


def test_duplicate_keys_are_reported():
    doc = load_doc("w.yml", "on: push\non: pull_request\njobs: {}\n")
    assert [(f.rule, f.line) for f in lint_doc(doc) if f.rule == "GHA1033"] == [("GHA1033", 2)]


def test_ignore_comments_above_and_trailing():
    base = ("on: push\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n")
    above = base + "      # workflowlint-ignore: GHA1001\n      - uses: foo/bar@v1\n"
    trailing = base + "      - uses: foo/bar@v1 # workflowlint-ignore: GHA1001\n"
    other = base + "      # workflowlint-ignore: GHA1003\n      - uses: foo/bar@v1\n"
    multi = base + "      # workflowlint-ignore: GHA1003, GHA1001\n      - uses: foo/bar@v1\n"
    assert not [f for f in lint_doc(load_doc("w.yml", above)) if f.rule == "GHA1001"]
    assert not [f for f in lint_doc(load_doc("w.yml", trailing)) if f.rule == "GHA1001"]
    assert [f for f in lint_doc(load_doc("w.yml", other)) if f.rule == "GHA1001"]
    assert not [f for f in lint_doc(load_doc("w.yml", multi)) if f.rule == "GHA1001"]


def test_ignore_above_a_step_covers_its_run_block():
    text = ("on: push\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n"
            "      # workflowlint-ignore: GHA1003\n      - run: |\n          echo ${{ github.head_ref }}\n")
    assert not [f for f in lint_doc(load_doc("w.yml", text)) if f.rule == "GHA1003"]


def test_disable_set_turns_rules_off():
    text = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
    all_ids = {f.rule for f in lint_doc(load_doc("w.yml", text))}
    assert {"GHA1004", "GHA1013", "GHA1021"} <= all_ids
    off = {f.rule for f in lint_doc(load_doc("w.yml", text), disabled=frozenset({"GHA1013", "GHA1021"}))}
    assert off == all_ids - {"GHA1013", "GHA1021"}


# ---------------------------------------------------------------------------------------------------------
# expressions


def test_find_expressions_handles_nested_quotes_and_braces():
    text = "a ${{ format('}}', x) }} b ${{ 'it''s }}' }} c ${{ y }}"
    bodies = [e.body.strip() for e in find_expressions(text)]
    assert bodies == ["format('}}', x)", "'it''s }}'", "y"]
    assert all(e.closed for e in find_expressions(text))


def test_unterminated_expression_is_marked():
    es = find_expressions("echo ${{ github.head_ref")
    assert len(es) == 1 and not es[0].closed


def test_tokens_skip_functions_strings_and_numbers():
    toks = [t.dotted for t in tokens("contains(github.event.issue.title, 'a.b') && 3.5 > matrix.v || fromJSON(x).y")]
    assert toks == ["github.event.issue.title", "matrix.v", "x"]


def test_tokens_normalize_brackets():
    assert [t.dotted for t in tokens("github.event['issue']['title']")] == ["github.event.issue.title"]
    assert [t.dotted for t in tokens("github.event.commits[0].message")] == ["github.event.commits.*.message"]
    assert [t.dotted for t in tokens("github.event.commits[ 0 ].author.name")] == ["github.event.commits.*.author.name"]
    assert [t.dotted for t in tokens("secrets.MY-KEY")] == ["secrets.MY-KEY"]


# (expression, expected severity or None). The documented dangerous contexts, and look-alikes that are safe.
INJECTION_TABLE = [
    ("github.event.issue.title", "error"),
    ("github.event.issue.body", "error"),
    ("github.event.pull_request.title", "error"),
    ("github.event.pull_request.body", "error"),
    ("github.event.pull_request.head.ref", "error"),
    ("github.event.pull_request.head.label", "error"),
    ("github.event.pull_request.head.repo.default_branch", "error"),
    ("github.event.pull_request.head.repo.description", "error"),
    ("github.event.pull_request.head.repo.homepage", "error"),
    ("github.event.comment.body", "error"),
    ("github.event.review.body", "error"),
    ("github.event.review_comment.body", "error"),
    ("github.event.discussion.title", "error"),
    ("github.event.discussion.body", "error"),
    ("github.event.pages[0].page_name", "error"),
    ("github.event.commits[0].message", "error"),
    ("github.event.commits[2].author.email", "error"),
    ("github.event.commits[2].author.name", "error"),
    ("github.event.head_commit.message", "error"),
    ("github.event.head_commit.author.email", "error"),
    ("github.event.head_commit.author.name", "error"),
    ("github.event.head_commit.committer.email", "error"),
    ("github.event.head_commit.committer.name", "error"),
    ("github.event.workflow_run.head_branch", "error"),
    ("github.event.workflow_run.display_title", "error"),
    ("github.event.workflow_run.head_commit.message", "error"),
    ("github.event.workflow_run.head_commit.author.email", "error"),
    ("github.event.workflow_run.head_repository.description", "error"),
    ("github.event.check_suite.head_branch", "error"),
    ("github.event.release.name", "error"),
    ("github.event.release.body", "error"),
    ("github.event.client_payload.anything", "error"),
    ("github.event.client_payload.deep.er.key", "error"),
    ("github.head_ref", "error"),
    ("GitHub.Head_Ref", "error"),
    ("github.ref_name", "warning"),
    ("github.event.inputs.name", "warning"),
    ("inputs.name", "warning"),
    # safe look-alikes
    ("github.event.issue.number", None),
    ("github.event.pull_request.number", None),
    ("github.event.pull_request.head.sha", None),
    ("github.event.pull_request.base.ref", None),
    ("github.event.pull_request.user.login", None),
    ("github.event.comment.id", None),
    ("github.event.head_commit.id", None),
    ("github.event.repository.name", None),
    ("github.sha", None),
    ("github.ref", None),
    ("github.actor", None),
    ("github.repository", None),
    ("github.event_name", None),
    ("runner.os", None),
    ("matrix.os", None),
    ("secrets.TOKEN", None),
    ("steps.build.outputs.result", None),
    ("env.TITLE", None),
    ("vars.NAME", None),
    ("needs.build.outputs.title", None),
]


@pytest.mark.parametrize("expr,severity", INJECTION_TABLE, ids=[e for e, _ in INJECTION_TABLE])
def test_injection_context_table(expr, severity):
    toks = tokens(expr)
    assert len(toks) == 1
    assert dangerous(toks[0]) == severity


def test_persist_credentials_only_complains_about_uploads_that_can_include_dot_git():
    def rules(path: str) -> set[str]:
        text = ("on: push\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n    steps:\n"
                "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n"
                "      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n"
                f"        with:\n          path: {path}\n")
        return {f.rule for f in lint_doc(load_doc("w.yml", text))}

    assert "GHA1009" not in rules("dist/")
    assert "GHA1009" not in rules("build/out.tar.gz")
    assert "GHA1009" in rules(".")
    assert "GHA1009" in rules("'**'")
    assert "GHA1009" in rules("./")


def test_redactor_leaves_permission_levels_alone():
    from workflowlint_mcp.report import redact

    assert redact("  id-token: write") == "  id-token: write"
    assert redact("  DB_PASSWORD: hunter2-fake") == "  DB_PASSWORD: <redacted>"
