"""workflows_overview: what is in these workflows, with secret NAMES only."""

from __future__ import annotations

from .expr import tokens
from .model import Doc, Node, walk_scalars
from .perms import effective, parse_permissions
from .rules import action_major, scalar_exprs, split_uses


def _names(doc: Doc, node: Node | None, root: str) -> set[str]:
    found: set[str] = set()
    if node is None:
        return found
    for key, sc in walk_scalars(node):
        for e, _line, _ in scalar_exprs(doc, sc, key):
            for t in tokens(e.body):
                if t.parts[0].lower() == root and len(t.parts) > 1 and t.parts[1] != "*":
                    found.add(t.parts[1])
    return found


def _uses_desc(doc: Doc, uses: str, line: int) -> str:
    if uses.startswith("./"):
        return f"{uses} (local)"
    if uses.startswith("docker://"):
        return f"{uses} ({'digest' if '@sha256:' in uses else 'tag'}-pinned container)"
    sp = split_uses(uses)
    if sp is None:
        return uses
    name, ref = sp
    if len(ref) in (40, 64) and all(c in "0123456789abcdefABCDEF" for c in ref):
        major = action_major(uses, doc.line_text(line))
        return f"{name}@{ref[:12]}... (pinned SHA" + (f", v{major}" if major is not None else "") + ")"
    return f"{name}@{ref} (NOT pinned to a SHA)"


def _perm_text(p: dict[str, str] | None) -> str:
    if p is None:
        return "not set"
    on = {k: v for k, v in sorted(p.items()) if v != "none"}
    return ", ".join(f"{k}: {v}" for k, v in on.items()) if on else "none"


def overview(docs: list[Doc]) -> str:
    out: list[str] = []
    total_jobs = 0
    unpinned = 0
    all_secrets: set[str] = set()
    actions: set[str] = set()
    for doc in docs:
        if doc.error is not None:
            out.append(f"== {doc.path}\n  INVALID YAML at line {doc.error.line}: {doc.error.message}\n")
            continue
        if doc.kind == "action":
            out.append(f"== {doc.path}  (composite/other action)")
            runs = doc.get("runs")
            using = runs.get("using") if runs else None
            out.append(f"  runs.using: {using.text if using else '?'}; {len(doc.steps)} step(s)")
            for s in doc.steps:
                if s.uses and s.uses_node:
                    out.append(f"    line {s.uses_node.line}: uses {_uses_desc(doc, s.uses, s.uses_node.line)}")
                    if s.action():
                        actions.add(s.uses.split("@")[0])
                    if "NOT pinned" in _uses_desc(doc, s.uses, s.uses_node.line):
                        unpinned += 1
            out.append("")
            continue
        name = doc.get("name")
        out.append(f"== {doc.path}" + (f"  ({name.text})" if name and name.text else ""))
        out.append("  triggers: " + (", ".join(doc.events) or "none"))
        wp = parse_permissions(doc.get("permissions"))
        out.append(f"  workflow permissions: {_perm_text(wp)}")
        out.append(f"  jobs ({len(doc.jobs)}):")
        for j in doc.jobs:
            total_jobs += 1
            eff, _src = effective(doc, j)
            ro = ", ".join(j.runs_on_labels()) or ("(reusable call)" if j.uses else "?")
            line = f"    {j.id} (line {j.line}): runs-on {ro}"
            if j.needs:
                line += f"; needs {', '.join(n.text for n in j.needs)}"
            out.append(line)
            if j.permissions is not None:
                out.append(f"      permissions: {_perm_text(parse_permissions(j.permissions))}")
            elif wp is None:
                out.append("      permissions: none declared (repository default)")
            if j.environment is not None:
                en = j.environment.get("name") if j.environment.is_map else j.environment
                out.append(f"      environment: {en.text if en else '?'}")
            if j.uses and j.uses_node:
                out.append(f"      calls {_uses_desc(doc, j.uses, j.uses_node.line)}")
                actions.add(j.uses.split("@")[0])
                if "NOT pinned" in _uses_desc(doc, j.uses, j.uses_node.line):
                    unpinned += 1
            for s in j.steps:
                if s.uses and s.uses_node:
                    d = _uses_desc(doc, s.uses, s.uses_node.line)
                    out.append(f"      line {s.uses_node.line}: uses {d}")
                    if s.action():
                        actions.add(s.uses.split("@")[0])
                    if "NOT pinned" in d:
                        unpinned += 1
            sec = _names(doc, j.node, "secrets")
            if sec:
                out.append("      secrets referenced (names only): " + ", ".join(sorted(sec)))
                all_secrets |= sec
        top_sec = _names(doc, doc.get("env"), "secrets")
        if top_sec:
            out.append("  workflow-level env references secrets (names only): " + ", ".join(sorted(top_sec)))
            all_secrets |= top_sec
        out.append("")
    out.append(f"Summary: {len(docs)} file(s), {total_jobs} job(s), {len(actions)} distinct action reference(s), "
               f"{unpinned} not pinned to a SHA, {len(all_secrets)} distinct secret name(s)"
               + (": " + ", ".join(sorted(all_secrets)) if all_secrets else "") + ". Secret values are never read.")
    return "\n".join(out)
