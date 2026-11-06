"""fix_preview: a unified diff of the safe automatic fixes. Text only; nothing is ever written."""

from __future__ import annotations

import bisect
import difflib
import re
from collections import Counter

from .errors import UserError
from .expr import Expr, dangerous, find_expressions, tokens
from .model import Doc, Job, Step, load_doc, script_lines
from .perms import infer_needs
from .rules import Finding, Loader, env_name, lint_doc

_SPLIT = re.compile(r"(\r\n|\n|\r)")
_SET_OUTPUT_Q = re.compile(r'^echo\s+"::set-output name=([A-Za-z0-9_-]+)::([^"]*)"\s*$')
_SET_OUTPUT_U = re.compile(r"^echo\s+::set-output name=([A-Za-z0-9_-]+)::([^\s\"']*)\s*$")


def split_keepends(text: str) -> list[str]:
    parts = _SPLIT.split(text)
    out = []
    for i in range(0, len(parts), 2):
        end = parts[i + 1] if i + 1 < len(parts) else ""
        if parts[i] or end:
            out.append(parts[i] + end)
    return out


class Editor:
    """Line-based edits that keep each line's original ending."""

    def __init__(self, text: str) -> None:
        self.lines = split_keepends(text)
        eol = "\n"
        for ln in self.lines:
            if ln.endswith("\r\n"):
                eol = "\r\n"
                break
            if ln.endswith("\n"):
                break
        self.eol = eol
        self.replaced: dict[int, str] = {}  # 1-based line -> new body (no ending)
        self.inserts: list[tuple[int, int, list[str]]] = []  # (after_line, order, bodies)
        self._n = 0

    def body(self, line: int) -> str:
        return self.replaced.get(line, self.lines[line - 1].rstrip("\r\n"))

    def set_body(self, line: int, text: str) -> None:
        self.replaced[line] = text

    def insert_after(self, line: int, bodies: list[str]) -> None:
        self._n += 1
        self.inserts.append((line, self._n, bodies))

    def result(self) -> str:
        out: list[str] = []
        by_line: dict[int, list[list[str]]] = {}
        for after, _, bodies in sorted(self.inserts, key=lambda t: (t[0], t[1])):
            by_line.setdefault(after, []).append(bodies)
        for b in by_line.get(0, []):
            out.extend(x + self.eol for x in b)
        for i, raw in enumerate(self.lines, 1):
            stripped = raw.rstrip("\r\n")
            ending = raw[len(stripped):]
            if i in by_line and not ending:
                ending = self.eol
            out.append(self.replaced.get(i, stripped) + ending)
            for b in by_line.get(i, []):
                out.extend(x + self.eol for x in b)
        return "".join(out)


def _quote_state_offsets(text: str, exprs: list[Expr]) -> dict[int, str]:
    """Shell quoting state ("" none, '"' double, "'" single) at each expression start."""
    starts = {e.start: e for e in exprs}
    state = ""
    out: dict[int, str] = {}
    i = 0
    n = len(text)
    while i < n:
        if i in starts:
            out[i] = state
            i = starts[i].end
            continue
        c = text[i]
        if c == "\\" and state != "'":
            i += 2
            continue
        if state == "":
            if c in "\"'":
                state = c
        elif c == state:
            state = ""
        i += 1
    return out


def _yaml_value(v: str) -> str:
    if re.search(r": | #|^\s|\s$|\t", v):
        return "'" + v.replace("'", "''") + "'"
    return v


def _fix_injection(doc: Doc, job: Job | None, step: Step, ed: Editor, manual: list[str]) -> int:
    node = step.run_node
    if node is None:
        return 0
    from .rules import _step_shell

    shell = _step_shell(job, step)
    sl = script_lines(node, doc.lines)
    text = "\n".join(s.text for s in sl)
    exprs = [e for e in find_expressions(text) if e.closed]
    bad = [e for e in exprs if any(dangerous(t) for t in tokens(e.body))]
    if not bad:
        return 0
    if shell not in ("bash", "sh", "pwsh", "powershell"):
        manual.append(f"line {step.line}: step uses shell `{shell}`; move the expression into `env:` by hand")
        return 0
    if not all(s.editable for s in sl):
        manual.append(f"line {step.line}: quoted or multi-line `run:` value; move the expression into `env:` by hand")
        return 0
    if any("\n" in text[e.start:e.end] for e in bad):
        manual.append(f"line {step.line}: an expression spans several lines; move it into `env:` by hand")
        return 0
    states = _quote_state_offsets(text, exprs)
    if any(states[e.start] == "'" for e in bad):
        manual.append(f"line {step.line}: the expression sits inside single quotes; restructure and move it into "
                      "`env:` by hand")
        return 0
    if step.env is not None and not (step.env.is_map and step.env.items):
        manual.append(f"line {step.line}: step has an inline `env:`; add the variable by hand")
        return 0
    if step.env is not None and step.env.items and step.env.line == step.env.key_line:
        manual.append(f"line {step.line}: step has an inline `env:`; add the variable by hand")
        return 0
    # names
    existing = {k: v.text for k, v in step.env.items.items()} if step.env is not None else {}
    names: dict[str, str] = {}  # expression text -> NAME
    used = set(existing)
    new_entries: list[tuple[str, str]] = []
    for e in bad:
        src = text[e.start:e.end]
        if src in names:
            continue
        toks = [t for t in tokens(e.body) if dangerous(t)]
        base = env_name(toks[0].parts)
        for k, v in existing.items():
            if v.strip() == src.strip():
                names[src] = k
                break
        else:
            name, i = base, 2
            while name in used:
                name, i = f"{base}_{i}", i + 1
            used.add(name)
            names[src] = name
            new_entries.append((name, src))
    # rewrite script lines
    offset = 0
    starts = []
    for s in sl:
        starts.append(offset)
        offset += len(s.text) + 1
    by_line: dict[int, list[Expr]] = {}
    for e in bad:
        by_line.setdefault(bisect.bisect_right(starts, e.start) - 1, []).append(e)
    for idx, exprs_here in by_line.items():
        s = sl[idx]
        line_start = starts[idx]
        new = s.text
        for e in sorted(exprs_here, key=lambda x: -x.start):
            name = names[text[e.start:e.end]]
            quoted = states[e.start] == '"'
            if shell in ("pwsh", "powershell"):
                ref = "${env:%s}" % name
            else:
                ref = "${%s}" % name
            if not quoted:
                ref = f'"{ref}"'
            new = new[:e.start - line_start] + ref + new[e.end - line_start:]
        if new != s.text:
            ed.set_body(s.line, ed.body(s.line)[:s.col] + new + ed.body(s.line)[s.col + len(s.text):])
    # env entries
    if new_entries:
        if step.env is not None:
            first = next(iter(step.env.items.values()))
            pad = " " * first.key_col
            ed.insert_after(step.env.key_line, [f"{pad}{n}: {_yaml_value(v)}" for n, v in new_entries])
        else:
            kc = node.key_col
            ed.insert_after(sl[-1].line, [" " * kc + "env:"] + [
                " " * (kc + 2) + f"{n}: {_yaml_value(v)}" for n, v in new_entries])
    return len(bad)


def _fix_set_output(doc: Doc, job: Job | None, step: Step, ed: Editor) -> int:
    if step.run_node is None:
        return 0
    from .rules import _step_shell

    if _step_shell(job, step) not in ("bash", "sh"):
        return 0
    n = 0
    for s in script_lines(step.run_node, doc.lines):
        if not s.editable:
            continue
        body = ed.body(s.line)
        text = body[s.col:]
        m = _SET_OUTPUT_Q.match(text.strip()) or _SET_OUTPUT_U.match(text.strip())
        if m:
            lead = text[:len(text) - len(text.lstrip())]
            ed.set_body(s.line, body[:s.col] + f'{lead}echo "{m.group(1)}={m.group(2)}" >> "$GITHUB_OUTPUT"')
            n += 1
    return n


def _fix_permissions(doc: Doc, ed: Editor, manual: list[str]) -> int:
    if doc.kind != "workflow" or doc.get("permissions") is not None or doc.jobs_node is None:
        return 0
    lacking = [j for j in doc.jobs if j.permissions is None]
    if not lacking:
        return 0
    for j in lacking:
        needs = infer_needs(j, doc)
        if not needs.conclusive or any(v == "write" for v in needs.scopes.values()):
            manual.append(f"line {j.line}: job `{j.id}` may need more than read access "
                          f"({'; '.join(needs.unknown[:1]) or 'write scopes inferred'}); choose its permissions by hand")
            return 0
    if doc.jobs_node.key_col != 0:
        return 0
    ed.insert_after(doc.jobs_node.key_line - 1, ["permissions:", "  contents: read", ""])
    return 1


def preview(path: str, text: str, loader: Loader | None, disabled: frozenset[str]) -> str:
    doc = load_doc(path, text)
    if doc.error is not None:
        raise UserError(f"{path} is not valid YAML (line {doc.error.line}: {doc.error.message}); fix that first.")
    before = lint_doc(doc, loader, disabled)
    ed = Editor(text)
    manual: list[str] = []
    applied: Counter[str] = Counter()
    if "GHA1004" not in disabled:
        applied["GHA1004"] += _fix_permissions(doc, ed, manual)
    for job, step in doc.all_steps():
        if "GHA1003" not in disabled:
            applied["GHA1003"] += _fix_injection(doc, job, step, ed, manual)
        if "GHA1011" not in disabled:
            applied["GHA1011"] += _fix_set_output(doc, job, step, ed)
    new_text = ed.result()
    if new_text == text:
        return _no_change(path, before, manual)
    after_doc = load_doc(path, new_text)
    if after_doc.error is not None:
        raise UserError(f"internal error: the automatic fix produced invalid YAML for {path} (line "
                        f"{after_doc.error.line}); no diff is shown. Please report this file.")
    after = lint_doc(after_doc, loader, disabled)
    old_keys = Counter(f.rule for f in before)
    new_keys = Counter(f.rule for f in after)
    introduced = [r for r in new_keys if new_keys[r] > old_keys.get(r, 0)]
    if introduced:
        raise UserError(f"internal error: the automatic fix would introduce new findings ({', '.join(introduced)}) "
                        f"in {path}; no diff is shown. Please report this file.")
    diff = "".join(difflib.unified_diff(split_keepends(text), split_keepends(new_text), f"a/{path}", f"b/{path}", n=2))
    if not diff.endswith("\n"):
        diff += "\n"
    removed = {r: old_keys[r] - new_keys.get(r, 0) for r in old_keys if old_keys[r] > new_keys.get(r, 0)}
    out = [f"fix_preview for {path}: unified diff below (not written to disk). Apply it yourself, e.g. `git apply`.",
           "", diff.rstrip("\n"), "",
           "Verified by re-linting the patched text: " + (
               ", ".join(f"{n} fewer {r}" for r, n in sorted(removed.items())) or "no change in findings") +
           "; no new findings introduced."]
    out += _remaining(after, manual)
    return "\n".join(out)


def _no_change(path: str, before: list[Finding], manual: list[str]) -> str:
    out = [f"fix_preview for {path}: no safe automatic fix applies."]
    out += _remaining(before, manual)
    return "\n".join(out)


def _remaining(findings: list[Finding], manual: list[str]) -> list[str]:
    out: list[str] = []
    if manual:
        out += ["", "Skipped fixes (need a human):"] + [f"  - {m}" for m in manual]
    if findings:
        out += ["", f"Still to fix by hand ({len(findings)}):"]
        out += [f"  - line {f.line} [{f.rule}] {f.severity}: {f.message[:140]}" for f in findings[:40]]
        if len(findings) > 40:
            out.append(f"  ... and {len(findings) - 40} more (run lint_workflows)")
    return out
