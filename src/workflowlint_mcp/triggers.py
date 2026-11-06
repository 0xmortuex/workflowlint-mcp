"""explain_triggers: when does this workflow run, in plain English."""

from __future__ import annotations

from datetime import datetime

from . import cron as cronmod
from .model import Doc, Node

_GENERIC = {
    "issues": "an issue is opened, edited, closed, labeled, etc.",
    "issue_comment": "someone comments on an issue or a pull request",
    "release": "a release is created, published, edited or deleted",
    "create": "a branch or tag is created",
    "delete": "a branch or tag is deleted",
    "fork": "someone forks the repository",
    "watch": "someone stars the repository",
    "label": "a label is created, edited or deleted",
    "milestone": "a milestone changes",
    "discussion": "a discussion is created or changed",
    "discussion_comment": "a discussion comment is created or changed",
    "deployment": "a deployment is created through the API",
    "deployment_status": "a deployment's status changes",
    "check_run": "a check run is created, completed or re-requested",
    "check_suite": "a check suite is completed or re-requested",
    "status": "a commit status changes",
    "merge_group": "a pull request enters a merge queue",
    "pull_request_review": "a pull request review is submitted, edited or dismissed",
    "pull_request_review_comment": "a comment on a pull request diff changes",
    "page_build": "GitHub Pages builds",
    "public": "the repository is made public",
    "gollum": "a wiki page is created or updated",
    "registry_package": "a package is published or updated",
    "branch_protection_rule": "a branch protection rule changes",
    "repository_dispatch": "an external service calls the repository dispatch API",
}

_DEFAULT_TYPES = {
    "pull_request": "opened, synchronize (new commits pushed), reopened",
    "pull_request_target": "opened, synchronize (new commits pushed), reopened",
}


def _list(n: Node | None) -> list[str]:
    if n is None:
        return []
    return [x.text for x in n.strings()]


def _filters(cfg: Node | None) -> list[str]:
    out: list[str] = []
    if cfg is None or not cfg.is_map:
        return out
    labels = (("branches", "branches matching"), ("branches-ignore", "except branches matching"),
              ("tags", "tags matching"), ("tags-ignore", "except tags matching"),
              ("paths", "when changed files match"), ("paths-ignore", "unless every changed file matches"))
    for key, label in labels:
        vals = _list(cfg.get(key))
        if vals:
            out.append(f"{label} {', '.join(vals)}")
    return out


def explain(doc: Doc, now: datetime) -> str:
    if doc.kind != "workflow":
        return f"{doc.path}: not a workflow (no triggers to explain)."
    name = (doc.get("name") or Node("scalar", 0, 0, 0)).text or doc.path
    lines = [f"Workflow: {name}  ({doc.path})"]
    if not doc.events:
        lines.append("  It has no `on:` trigger, so it never runs.")
        return "\n".join(lines)
    for ev, cfg in doc.events.items():
        lines.append("")
        lines.append(f"- {ev}")
        if ev == "push":
            filt = _filters(cfg)
            only_tags = cfg is not None and cfg.is_map and (cfg.get("tags") or cfg.get("tags-ignore")) and not (
                cfg.get("branches") or cfg.get("branches-ignore"))
            lines.append("    Runs when commits or tags are pushed" + (": " + "; ".join(filt) if filt else
                                                                       " to any branch or tag."))
            if only_tags:
                lines.append("    Only tag filters are set, so plain branch pushes do NOT trigger it.")
            lines.append("    The workflow file used is the one at the pushed commit.")
        elif ev in ("pull_request", "pull_request_target"):
            types = _list(cfg.get("types")) if cfg is not None and cfg.is_map else []
            filt = _filters(cfg)
            lines.append(f"    Runs when a pull request is {', '.join(types) if types else _DEFAULT_TYPES[ev]}"
                         + (f" (target {'; '.join(filt)})" if filt else "") + ".")
            if ev == "pull_request":
                lines.append("    Runs on the merge of the PR into its base branch. For pull requests from forks the "
                             "token is read-only and secrets are not available; first-time contributors need "
                             "approval before it runs.")
            else:
                lines.append("    Runs the workflow file from the BASE branch, with secrets and a write-capable token, "
                             "even for fork PRs. Never check out or execute PR code here.")
        elif ev == "workflow_dispatch":
            lines.append("    Runs when someone clicks 'Run workflow' (or calls the API / gh workflow run).")
            ins = cfg.get("inputs") if cfg is not None and cfg.is_map else None
            if ins is not None and ins.is_map:
                for k, v in ins.items.items():
                    typ = (v.get("type") or Node("scalar", 0, 0, 0)).text or "string"
                    req = v.get("required")
                    default = v.get("default")
                    extra = ", required" if req is not None and req.is_true() else ""
                    extra += f", default {default.text!r}" if default is not None and default.text else ""
                    lines.append(f"    input {k}: {typ}{extra}")
            lines.append("    The file must exist on the default branch for the button to appear.")
        elif ev == "workflow_call":
            lines.append("    Reusable workflow: runs when another workflow calls it with `uses:`.")
            if cfg is not None and cfg.is_map:
                for section in ("inputs", "secrets", "outputs"):
                    sec = cfg.get(section)
                    if sec is not None and sec.is_map:
                        lines.append(f"    {section}: " + ", ".join(sec.items))
        elif ev == "workflow_run":
            wfs = _list(cfg.get("workflows")) if cfg is not None and cfg.is_map else []
            types = _list(cfg.get("types")) if cfg is not None and cfg.is_map else []
            filt = _filters(cfg)
            lines.append(f"    Runs when workflow(s) {', '.join(wfs) or '(none listed)'} are "
                         f"{', '.join(types) or 'requested or completed'}" + (f" ({'; '.join(filt)})" if filt else "")
                         + ".")
            lines.append("    Uses the workflow file from the default branch, with secrets and a write token, even "
                         "when the triggering run came from a fork. Treat anything from that run as untrusted.")
        elif ev == "schedule":
            lines.append("    Runs on a timetable (always UTC):")
            crons = cfg.seq if cfg is not None and cfg.is_seq else []
            for item in crons:
                c = item.get("cron") if item.is_map else None
                if c is None:
                    lines.append("    (schedule entry without a `cron:` key)")
                    continue
                try:
                    cr = cronmod.parse_cron(c.text)
                except cronmod.CronError as e:
                    lines.append(f"    cron '{c.text}' (line {c.line}) is INVALID: {e}")
                    continue
                lines.append(f"    cron '{c.text}' (line {c.line}): {cronmod.explain_cron(cr)}")
                runs = cronmod.next_runs(cr, now, 5)
                if runs:
                    lines.append("      next runs: " + "; ".join(cronmod.format_time(t) for t in runs))
                else:
                    lines.append("      this expression never matches a real date (e.g. February 31)")
                for note in cronmod.congestion_notes(cr, now):
                    lines.append(f"      note: {note}")
            lines.append("    Scheduled workflows only run from the default branch's copy of the file, and GitHub "
                         "disables them after 60 days without repository activity (public repositories). Runs can "
                         "start late when GitHub is busy.")
        elif ev == "repository_dispatch":
            types = _list(cfg.get("types")) if cfg is not None and cfg.is_map else []
            lines.append("    Runs when an external service calls the repository_dispatch API"
                         + (f" with event_type {', '.join(types)}" if types else "") + ".")
        else:
            types = _list(cfg.get("types")) if cfg is not None and cfg.is_map else []
            what = _GENERIC.get(ev, f"a `{ev}` event happens")
            lines.append(f"    Runs when {what}" + (f" (activity types: {', '.join(types)})" if types else "") + ".")
    return "\n".join(lines)
