"""Every bad workflow: the marked rule must fire on the marked line, written to a real file and linted through
the same sandbox/discovery path the server uses."""

from __future__ import annotations

import re

import pytest
from bad_cases import CASES

from workflowlint_mcp.files import Sandbox
from workflowlint_mcp.model import load_doc
from workflowlint_mcp.rules import RULES, lint_doc

from conftest import write

MARK = re.compile(r"#@([A-Z0-9@,\-]+)\s*$")


def expected_markers(text: str) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for n, line in enumerate(text.split("\n"), 1):
        m = MARK.search(line)
        if not m:
            continue
        for spec in m.group(1).split(","):
            rule, _, shift = spec.partition("@")
            out.setdefault(rule, set()).add(n + (int(shift) if shift else 0))
    return out


def test_at_least_fifty_bad_cases_and_every_rule_is_covered():
    assert len(CASES) >= 50
    covered = set()
    for _, text, _ in CASES:
        covered |= set(expected_markers(text))
    missing = sorted(set(RULES) - covered - {"GHA1000", "GHA1022"})
    assert not missing, f"rules without a bad case: {missing}"


@pytest.mark.parametrize("name,text,filename", CASES, ids=[c[0] for c in CASES])
def test_bad_workflow(tmp_path, name, text, filename):
    write(str(tmp_path / filename), text)
    sb = Sandbox(str(tmp_path))
    real, content = sb.read_text(filename)
    doc = load_doc(sb.display(real), content)
    assert doc.error is None, (doc.error.message, doc.error.line) if doc.error else None
    found = lint_doc(doc)
    want = expected_markers(text)
    assert want, "case has no markers"
    for rule, lines in want.items():
        got = {f.line for f in found if f.rule == rule}
        assert lines <= got, f"{rule}: expected lines {sorted(lines)}, got {sorted(got)}\n" + "\n".join(
            f"{f.rule}@{f.line} {f.message[:80]}" for f in found)
        assert got <= lines, f"{rule}: unexpected extra lines {sorted(got - lines)}"
        for f in found:
            if f.rule == rule:
                assert f.fix and f.message and f.severity in ("error", "warning", "info")
