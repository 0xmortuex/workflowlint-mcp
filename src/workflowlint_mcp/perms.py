"""GITHUB_TOKEN permissions: what each job is granted and what it appears to need."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Doc, Job, Node, Step, logical_lines, script_lines
from .tables import ACTION_NEEDS, ALL_SCOPES, COMMAND_NEEDS, PERMISSION_SCOPES

_RANK = {"none": 0, "read": 1, "write": 2}
_CMD_RES = [(re.compile(p), s, lv) for p, s, lv in COMMAND_NEEDS]


@dataclass
class Needs:
    scopes: dict[str, str] = field(default_factory=dict)
    reasons: dict[str, list[str]] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)  # why the inference is not conclusive

    @property
    def conclusive(self) -> bool:
        return not self.unknown

    def add(self, scope: str, level: str, why: str) -> None:
        if _RANK[level] > _RANK.get(self.scopes.get(scope, "none"), 0):
            self.scopes[scope] = level
        self.reasons.setdefault(scope, []).append(why)


def _needs_for_step(step: Step, doc: Doc, needs: Needs) -> None:
    if step.uses:
        if step.uses.startswith("./"):
            needs.unknown.append(f"line {step.line}: local action {step.uses} (cannot see what it needs)")
            return
        if step.uses.startswith("docker://"):
            return
        full = step.action_path()
        key = full if full in ACTION_NEEDS else (step.action() or "")
        if key not in ACTION_NEEDS:
            needs.unknown.append(f"line {step.line}: {step.action() or step.uses} (not in the known-actions table)")
            return
        for scope, level in ACTION_NEEDS[key].items():
            needs.add(scope, level, f"{key} (line {step.line})")
        if key == "actions/github-script":
            needs.unknown.append(f"line {step.line}: actions/github-script can call any API")
    if step.run_node is not None:
        for line_no, text in logical_lines(script_lines(step.run_node, doc.lines)):
            for rx, scope, level in _CMD_RES:
                if rx.search(text):
                    needs.add(scope, level, f"`{text.strip()[:60]}` (line {line_no})")
            if re.search(r"\bgh\s+api\b|api\.github\.com", text):
                needs.unknown.append(f"line {line_no}: calls the GitHub API directly")
            elif re.search(r"\bgh\s+\w+", text) and not any(rx.search(text) for rx, _, _ in _CMD_RES):
                needs.unknown.append(f"line {line_no}: uses the gh CLI (`{text.strip()[:40]}`)")
    if step.uses and step.action() == "actions/github-script":
        needs.unknown.append(f"line {step.line}: actions/github-script can call any API")


def infer_needs(job: Job, doc: Doc) -> Needs:
    needs = Needs()
    if job.uses:
        needs.unknown.append(f"line {job.line}: reusable workflow {job.uses} decides its own needs")
    for step in job.steps:
        _needs_for_step(step, doc, needs)
    # a job that checks out nothing needs nothing for contents
    return needs


def parse_permissions(node: Node | None) -> dict[str, str] | None:
    """scope -> level for a `permissions:` node; None if absent. `read-all`/`write-all` expand to all scopes."""
    if node is None:
        return None
    if node.is_scalar:
        word = (node.text or "").strip()
        if word == "read-all":
            return {s: "read" for s in ALL_SCOPES if s != "id-token"}
        if word == "write-all":
            return {s: "write" for s in ALL_SCOPES}
        return {}
    if node.is_map:
        return {k: (v.text or "none") for k, v in node.items.items()}
    return {}


def effective(doc: Doc, job: Job) -> tuple[dict[str, str] | None, str]:
    """(permissions, where it comes from). None means the repository/org default applies."""
    p = parse_permissions(job.permissions)
    if p is not None:
        return p, f"job `permissions:` (line {job.permissions.key_line})" if job.permissions else "job"
    wf = doc.get("permissions")
    p = parse_permissions(wf)
    if p is not None and wf is not None:
        return p, f"workflow `permissions:` (line {wf.key_line})"
    return None, "none declared: the repository/organization default applies (write-all unless an admin chose " \
                 "the restricted default)"


def _fmt_perms(p: dict[str, str]) -> str:
    on = {k: v for k, v in sorted(p.items()) if v != "none"}
    if not on:
        return "no access"
    if len(on) == len(ALL_SCOPES) - 1 and all(v == "read" for v in on.values()):
        return "read on everything (read-all)"
    return ", ".join(f"{k}: {v}" for k, v in on.items())


def suggestion(needs: Needs) -> list[str]:
    if not needs.scopes:
        return ["permissions: {}"]
    return ["permissions:"] + [f"  {k}: {v}" for k, v in sorted(needs.scopes.items())]


def review(docs: list[Doc]) -> str:
    out: list[str] = []
    for doc in docs:
        if doc.kind != "workflow":
            continue
        out.append(f"== {doc.path}")
        wf = doc.get("permissions")
        wp = parse_permissions(wf)
        if wp is None:
            out.append("  workflow level: no `permissions:` key")
        else:
            out.append(f"  workflow level (line {wf.key_line if wf else 0}): {_fmt_perms(wp)}")
        if not doc.jobs:
            out.append("  (no jobs)")
        for job in doc.jobs:
            eff, src = effective(doc, job)
            out.append(f"  job {job.id} (line {job.line})")
            if eff is None:
                out.append(f"    granted : unknown - {src}")
            else:
                out.append(f"    granted : {_fmt_perms(eff)}  <- {src}")
            needs = infer_needs(job, doc)
            if needs.scopes:
                out.append("    needs   : " + ", ".join(f"{k}: {v}" for k, v in sorted(needs.scopes.items())))
                for scope, why in sorted(needs.reasons.items()):
                    out.append(f"              {scope}: {'; '.join(why[:3])}")
            else:
                out.append("    needs   : nothing from GITHUB_TOKEN that I can see")
            excess: list[str] = []
            missing: list[str] = []
            if eff is not None:
                for scope, level in sorted(eff.items()):
                    if level == "write" and _RANK.get(needs.scopes.get(scope, "none"), 0) < 2:
                        excess.append(scope)
                for scope, level in sorted(needs.scopes.items()):
                    if _RANK.get(eff.get(scope, "none"), 0) < _RANK[level]:
                        missing.append(f"{scope}: {level}")
            if excess:
                tail = "" if needs.conclusive else " (inference is partial, so confirm before removing)"
                out.append("    possibly more than needed: write on " + ", ".join(excess) + tail)
            if missing:
                out.append("    would FAIL: needs " + ", ".join(missing) + " but is not granted it")
            if needs.unknown:
                out.append("    inference is partial because:")
                out.extend(f"      - {u}" for u in needs.unknown[:5])
            out.append("    least-privilege suggestion for this job:" + (
                "" if needs.conclusive else " (minimum known; add what the unknown steps need)"))
            out.extend(f"      {line}" for line in suggestion(needs))
        out.append("")
    out.append("Notes: fork pull requests always get a read-only token regardless of `permissions:`. A job-level "
               "`permissions:` replaces the workflow-level one entirely (unlisted scopes become none). The needs "
               "column is inferred from known actions and gh/git commands; it is a heuristic, not a proof.")
    return "\n".join(out)


def valid_scope(name: str) -> bool:
    return name in PERMISSION_SCOPES
