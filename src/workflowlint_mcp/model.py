"""A workflow model that remembers where everything came from.

PyYAML's `safe_load` implements YAML 1.1: the key `on` becomes the boolean True, `yes`/`no`/`off` become
booleans, and `3.10` becomes the float 3.1. GitHub reads workflows as YAML 1.2-ish, so none of that is
wanted here. We therefore stop at PyYAML's *composer* (which only builds a node graph with line marks,
never Python objects) and convert nodes ourselves: keys stay strings, only `true`/`false` are booleans.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import yaml

MAX_NODES = 100_000  # after alias expansion: stops "billion laughs" documents
MAX_DEPTH = 60
MAX_CHARS = 20_000_000  # total scalar text after alias expansion

_INT = re.compile(r"[-+]?[0-9]+\Z")
_FLOAT = re.compile(r"[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?\Z")


class YamlProblem(Exception):
    def __init__(self, line: int, message: str) -> None:
        super().__init__(message)
        self.line = line
        self.message = message


class Node:
    """One YAML value. `kind` is "scalar", "map" or "seq"."""

    __slots__ = ("kind", "line", "end_line", "col", "key_line", "key_col", "value", "text", "style", "items",
                 "seq", "tag")

    def __init__(self, kind: str, line: int, end_line: int, col: int) -> None:
        self.kind = kind
        self.line = line
        self.end_line = end_line
        self.col = col
        self.key_line = line
        self.key_col = col
        self.value: Any = None  # converted scalar
        self.text = ""  # raw scalar text
        self.style = ""  # "" plain, "|" literal, ">" folded, "'" or '"' quoted
        self.items: dict[str, Node] = {}
        self.seq: list[Node] = []
        self.tag = ""  # a non-standard "!tag", if any

    @property
    def is_map(self) -> bool:
        return self.kind == "map"

    @property
    def is_seq(self) -> bool:
        return self.kind == "seq"

    @property
    def is_scalar(self) -> bool:
        return self.kind == "scalar"

    def get(self, key: str) -> Node | None:
        return self.items.get(key) if self.kind == "map" else None

    def string(self) -> str | None:
        """The scalar as text (numbers and booleans are rendered the way they were written)."""
        return self.text if self.kind == "scalar" and self.value is not None else None

    def is_true(self) -> bool:
        return self.kind == "scalar" and (
            self.value is True or (isinstance(self.value, str) and self.value.lower() == "true"))

    def is_false(self) -> bool:
        return self.kind == "scalar" and (
            self.value is False or (isinstance(self.value, str) and self.value.lower() == "false"))

    def strings(self) -> list[Node]:
        """Scalar children: the node itself if it is a scalar, else the scalar items of a sequence."""
        if self.kind == "scalar":
            return [self]
        if self.kind == "seq":
            return [n for n in self.seq if n.kind == "scalar"]
        return []


def _scalar(n: yaml.ScalarNode) -> Node:
    node = Node("scalar", n.start_mark.line + 1, n.end_mark.line + 1, n.start_mark.column)
    text: str = n.value
    node.text = text
    node.style = n.style or ""
    if n.tag.startswith("!"):
        node.tag = n.tag
        node.value = text
        return node
    if node.style:
        node.value = text
    elif text in ("true", "True", "TRUE"):
        node.value = True
    elif text in ("false", "False", "FALSE"):
        node.value = False
    elif text in ("", "~", "null", "Null", "NULL"):
        node.value = None
    elif _INT.match(text):
        node.value = int(text)
    elif _FLOAT.match(text):
        node.value = float(text)
    else:
        node.value = text
    return node


class _State:
    def __init__(self) -> None:
        self.count = 0
        self.chars = 0
        self.dups: list[tuple[str, int]] = []


def _convert(n: yaml.Node, st: _State, depth: int) -> Node:
    st.count += 1
    line = n.start_mark.line + 1
    if st.count > MAX_NODES:
        raise YamlProblem(line, f"the document expands to more than {MAX_NODES} nodes (alias bomb?)")
    if depth > MAX_DEPTH:
        raise YamlProblem(line, f"nesting deeper than {MAX_DEPTH} levels")
    if isinstance(n, yaml.ScalarNode):
        st.chars += len(n.value)
        if st.chars > MAX_CHARS:
            raise YamlProblem(line, f"the document expands to more than {MAX_CHARS} characters (alias bomb?)")
        return _scalar(n)
    if isinstance(n, yaml.SequenceNode):
        node = Node("seq", line, n.end_mark.line + 1, n.start_mark.column)
        node.seq = [_convert(c, st, depth + 1) for c in n.value]
        return node
    if isinstance(n, yaml.MappingNode):
        node = Node("map", line, n.end_mark.line + 1, n.start_mark.column)
        merged: list[tuple[str, Node]] = []
        for k, v in n.value:
            if not isinstance(k, yaml.ScalarNode):
                raise YamlProblem(k.start_mark.line + 1, "mapping keys must be plain strings")
            if k.tag == "tag:yaml.org,2002:merge":
                sources = v.value if isinstance(v, yaml.SequenceNode) else [v]
                for src in sources:
                    sub = _convert(src, st, depth + 1)
                    if sub.kind != "map":
                        raise YamlProblem(src.start_mark.line + 1, "a merge key (<<) needs a mapping")
                    merged.extend(sub.items.items())
                continue
            child = _convert(v, st, depth + 1)
            child.key_line = k.start_mark.line + 1
            child.key_col = k.start_mark.column
            key = k.value
            if key in node.items:
                st.dups.append((key, child.key_line))
            node.items[key] = child
        for key, child in merged:
            node.items.setdefault(key, child)
        return node
    raise YamlProblem(line, "unsupported YAML node")


def parse_yaml(text: str) -> tuple[Node, list[tuple[str, int]]]:
    """Parse one YAML document into Nodes (plus duplicate keys). Raises YamlProblem with a line."""
    try:
        composed = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None) or getattr(e, "context_mark", None)
        problem = getattr(e, "problem", None) or str(e)
        raise YamlProblem(mark.line + 1 if mark else 1, str(problem).strip()) from e
    except RecursionError as e:
        raise YamlProblem(1, f"nesting deeper than {MAX_DEPTH} levels") from e
    if composed is None:
        raise YamlProblem(1, "the file is empty")
    st = _State()
    try:
        root = _convert(composed, st, 0)
    except RecursionError as e:
        raise YamlProblem(1, f"nesting deeper than {MAX_DEPTH} levels") from e
    return root, st.dups


# ---------------------------------------------------------------------------------------------------------
# Scripts: the lines of a `run:` block with real file line numbers


@dataclass
class ScriptLine:
    line: int  # 1-based line in the file
    text: str  # line content with the block indentation removed
    col: int  # raw_line[col:] starts with `text` (when editable)
    editable: bool


def script_lines(node: Node, lines: list[str]) -> list[ScriptLine]:
    """The lines of a scalar, mapped to file line numbers. Literal/folded blocks are read from the source
    text so numbering inside `run: |` is exact."""
    if node.kind != "scalar" or node.value is None:
        return []
    if node.style in ("|", ">"):
        first = node.line + 1
        last = min(node.end_line - 1, len(lines))
        raw = [lines[i - 1].rstrip("\r\n") for i in range(first, last + 1)]
        while raw and not raw[-1].strip():
            raw.pop()
        indents = [len(r) - len(r.lstrip(" ")) for r in raw if r.strip()]
        ind = min(indents) if indents else 0
        return [ScriptLine(first + i, r[ind:], ind, True) for i, r in enumerate(raw)]
    parts = node.text.split("\n")
    out = []
    for i, part in enumerate(parts):
        editable = False
        col = node.col
        if i == 0 and len(parts) == 1 and not node.style and 0 < node.line <= len(lines):
            raw_line = lines[node.line - 1]
            editable = raw_line[col:col + len(part)] == part
        out.append(ScriptLine(node.line + i, part, col, editable))
    return out


def logical_lines(sl: list[ScriptLine]) -> list[tuple[int, str]]:
    """Join backslash-continued lines. Returns (first line number, joined text)."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 0
    for s in sl:
        if not buf:
            start = s.line
        if s.text.endswith("\\"):
            buf.append(s.text[:-1])
            continue
        buf.append(s.text)
        out.append((start, " ".join(b.strip() if i else b for i, b in enumerate(buf))))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


# ---------------------------------------------------------------------------------------------------------
# Workflow / job / step views

_EMPTY = Node("scalar", 0, 0, 0)


class Step:
    def __init__(self, node: Node, index: int, in_action: bool = False) -> None:
        self.node = node
        self.index = index
        self.line = node.line
        self.in_action = in_action
        self.uses_node = node.get("uses")
        self.run_node = node.get("run")
        self.uses = self.uses_node.string() if self.uses_node else None
        self.with_ = node.get("with")
        self.env = node.get("env")
        self.if_node = node.get("if")
        self.name = (node.get("name") or _EMPTY).text
        sh = node.get("shell")
        self.shell = sh.text if sh and sh.is_scalar else None

    def with_get(self, key: str) -> Node | None:
        return self.with_.get(key) if self.with_ is not None else None

    def action(self) -> str | None:
        """owner/repo (lowercase, without sub-path) of a `uses:`, or None for local / docker steps."""
        if not self.uses or self.uses.startswith(("./", "../", "docker://")):
            return None
        name = self.uses.split("@", 1)[0]
        bits = name.split("/")
        return "/".join(bits[:2]).lower() if len(bits) >= 2 else name.lower()

    def action_path(self) -> str:
        """Full action name without the ref, lowercase (owner/repo/sub/path)."""
        return (self.uses or "").split("@", 1)[0].lower()


class Job:
    def __init__(self, job_id: str, node: Node) -> None:
        self.id = job_id
        self.node = node
        self.line = node.key_line
        self.uses_node = node.get("uses")
        self.uses = self.uses_node.string() if self.uses_node else None
        self.runs_on = node.get("runs-on")
        self.permissions = node.get("permissions")
        self.timeout = node.get("timeout-minutes")
        self.concurrency = node.get("concurrency")
        self.environment = node.get("environment")
        self.env = node.get("env")
        self.strategy = node.get("strategy")
        self.if_node = node.get("if")
        self.name = (node.get("name") or _EMPTY).text
        steps = node.get("steps")
        self.steps: list[Step] = []
        if steps is not None and steps.is_seq:
            self.steps = [Step(s, i) for i, s in enumerate(steps.seq) if s.is_map]
        self.needs: list[Node] = []
        needs = node.get("needs")
        if needs is not None:
            self.needs = needs.strings()

    def runs_on_labels(self) -> list[str]:
        ro = self.runs_on
        if ro is None:
            return []
        if ro.is_scalar:
            return [ro.text]
        if ro.is_seq:
            return [n.text for n in ro.seq if n.is_scalar]
        labels = ro.get("labels")
        if labels is not None:
            return [n.text for n in labels.strings()]
        return []

    def default_shell(self) -> str | None:
        d = self.node.get("defaults")
        run = d.get("run") if d else None
        sh = run.get("shell") if run else None
        return sh.text if sh and sh.is_scalar else None


@dataclass
class Doc:
    path: str  # display path
    text: str
    lines: list[str]
    kind: str  # "workflow" | "action" | "invalid"
    root: Node | None = None
    error: YamlProblem | None = None
    events: dict[str, Node | None] = field(default_factory=dict)
    on_node: Node | None = None
    jobs: list[Job] = field(default_factory=list)
    jobs_node: Node | None = None
    steps: list[Step] = field(default_factory=list)  # composite action steps
    dups: list[tuple[str, int]] = field(default_factory=list)

    def get(self, key: str) -> Node | None:
        return self.root.get(key) if self.root else None

    def all_steps(self) -> list[tuple[Job | None, Step]]:
        out: list[tuple[Job | None, Step]] = [(None, s) for s in self.steps]
        for j in self.jobs:
            out.extend((j, s) for s in j.steps)
        return out

    def line_text(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""


def load_doc(display: str, text: str) -> Doc:
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    doc = Doc(display, text, lines, "invalid")
    try:
        root, dups = parse_yaml(text)
    except YamlProblem as e:
        doc.error = e
        return doc
    doc.dups = dups
    doc.root = root
    base = os.path.basename(display).lower()
    if root.kind != "map":
        doc.error = YamlProblem(root.line, "the top level of a workflow must be a mapping")
        return doc
    is_action = base in ("action.yml", "action.yaml") or ("runs" in root.items and "jobs" not in root.items)
    doc.kind = "action" if is_action else "workflow"
    if is_action:
        runs = root.get("runs")
        st = runs.get("steps") if runs else None
        if st is not None and st.is_seq:
            doc.steps = [Step(s, i, True) for i, s in enumerate(st.seq) if s.is_map]
        return doc
    on = root.get("on")
    doc.on_node = on
    if on is not None:
        if on.is_scalar and on.text:
            doc.events[on.text] = None
        elif on.is_seq:
            for n in on.seq:
                if n.is_scalar:
                    doc.events[n.text] = None
        elif on.is_map:
            for k, v in on.items.items():
                doc.events[k] = v if not (v.is_scalar and v.value is None) else None
    jobs = root.get("jobs")
    doc.jobs_node = jobs
    if jobs is not None and jobs.is_map:
        doc.jobs = [Job(k, v) for k, v in jobs.items.items() if v.is_map]
    return doc


def walk_scalars(node: Node, key: str = "", depth: int = 0) -> Iterator[tuple[str, Node]]:
    """Yield (key, scalar Node) for every scalar below `node`; key is the nearest mapping key."""
    if depth > MAX_DEPTH:
        return
    if node.kind == "scalar":
        yield key, node
    elif node.kind == "seq":
        for c in node.seq:
            yield from walk_scalars(c, key, depth + 1)
    else:
        for k, c in node.items.items():
            yield from walk_scalars(c, k, depth + 1)
