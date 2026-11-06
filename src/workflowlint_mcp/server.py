"""workflowlint-mcp: static GitHub Actions workflow auditing for AI agents (offline by default, read-only)."""

from __future__ import annotations

import argparse
import functools
import os
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from .errors import UserError
from .files import Sandbox, discover, repo_root
from .fixes import preview as _preview
from .graph import render as _render_graph
from .model import Doc, load_doc
from .overview import overview as _overview
from .perms import review as _review
from .pinning import DEFAULT_API, GitHubClient, plan as _plan, validate_base_url
from .report import clip, format_findings
from .rules import RULES, Loader, lint_doc
from .tables import RETIRED_AS_OF
from .triggers import explain as _explain

mcp = MCPServer(
    "workflowlint",
    instructions=(
        "Audit GitHub Actions workflows (.github/workflows/*.yml and local composite actions) for security and "
        "correctness problems. Read-only and offline by default. Pass a workflow file, a repo root, or the "
        "workflows directory (relative to the server's --dir, or absolute inside it). Typical flow: "
        "workflows_overview to see what exists, lint_workflows for rule IDs + line numbers + concrete fixes, "
        "fix_preview for a diff of the safe fixes, pin_actions_plan to pin actions to commit SHAs, "
        "permissions_review for least-privilege GITHUB_TOKEN permissions, explain_triggers for when a workflow "
        "runs (cron explained with next run times), job_graph for the needs graph. Silence a finding with a "
        "`# workflowlint-ignore: GHA1003` comment on the line above it."
    ),
)

_sandbox: Sandbox | None = None
_disabled: frozenset[str] = frozenset()
_client: GitHubClient | None = None

F = TypeVar("F", bound=Callable[..., Any])

_EXPECTED = (UserError, OSError, RecursionError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except RecursionError as e:
            raise ToolError("The file is nested too deeply to analyze.") from e
        except _EXPECTED as e:
            raise ToolError(str(e)) from e

    mcp.tool()(wrapper)
    return fn


def configure(directory: str | None, disable: Sequence[str] = (), api_url: str | None = None) -> None:
    global _sandbox, _disabled, _client
    _sandbox = Sandbox(directory or os.getcwd())
    unknown = sorted(d for d in disable if d not in RULES)
    if unknown:
        raise UserError(f"unknown rule id(s): {', '.join(unknown)}. Known: {', '.join(sorted(RULES))}")
    _disabled = frozenset(disable)
    _client = GitHubClient(validate_base_url(api_url or DEFAULT_API), os.environ.get("GITHUB_TOKEN") or None)


def _sb() -> Sandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = Sandbox(os.getcwd())
    return _sandbox


def _gh() -> GitHubClient:
    global _client
    if _client is None:
        _client = GitHubClient(DEFAULT_API, os.environ.get("GITHUB_TOKEN") or None)
    return _client


def load_docs(sb: Sandbox, path: str) -> list[tuple[str, Doc]]:
    out = []
    for real in discover(sb, path):
        _, text = sb.read_text(real)
        out.append((real, load_doc(sb.display(real), text)))
    return out


def make_loader(sb: Sandbox, real_file: str) -> Loader:
    root = repo_root(real_file)

    def load(rel: str) -> Doc | None:
        if root is None:
            return None
        target = os.path.join(root, rel.replace("/", os.sep))
        try:
            real, text = sb.read_text(target)
        except UserError:
            return None
        return load_doc(sb.display(real), text)

    return load


@tool
def workflows_overview(path: str = ".") -> str:
    """Summarize GitHub Actions workflows: triggers, jobs with runners and `needs`, permissions per job,
    every action used (version, whether pinned to a commit SHA), environments, and the NAMES of the secrets
    each job references (values are never read). Also covers local composite actions under .github/actions.
    `path` is a workflow file, a repo root containing .github/workflows, or the workflows directory.
    Invalid YAML is reported with its line instead of failing. Start here."""
    return clip(_overview([d for _, d in load_docs(_sb(), path)]))


@tool
def lint_workflows(path: str = ".") -> str:
    """Lint workflows and composite actions with 33 rules (GHA1001-GHA1033). Each finding has a rule id,
    severity (error/warning/info), file:line (exact line inside multi-line `run: |` blocks), an
    explanation and a concrete fix. Covers: actions not pinned to a commit SHA, pwn requests
    (pull_request_target / workflow_run + checkout of PR code), script injection through
    github.event.* / head_ref / inputs inside run: or github-script, missing or write-all permissions,
    secrets: inherit, secrets echoed or on command lines, curl | bash, checkout credentials left behind,
    self-hosted runners on PR triggers, deprecated commands (set-output, set-env), timeouts, concurrency,
    needs mistakes and cycles, always-true if: expressions, unknown/misspelled contexts, matrix size,
    reusable-workflow input/secret mismatches, retired action versions (dated table), cache keys,
    continue-on-error, unquoted 3.10 versions, invalid cron. Suppress with
    `# workflowlint-ignore: GHA1003` above the line. Never modifies anything."""
    sb = _sb()
    found = []
    docs = load_docs(sb, path)
    for real, doc in docs:
        found.extend(lint_doc(doc, make_loader(sb, real), _disabled))
    found.sort(key=lambda f: (f.file, f.line, f.rule))
    note = (f"{len(docs)} file(s) checked. Retired-action table as of {RETIRED_AS_OF}. Unpinned-action and "
            "permission findings depend on repository settings you cannot see from files: treat them as review "
            "prompts, not proof.")
    return format_findings(f"Workflows under {path}", found, note)


@tool
def explain_triggers(path: str) -> str:
    """Explain in plain English when each workflow runs: push/PR filters, which pull request types, fork
    behaviour, manual inputs, reusable-workflow interface, workflow_run chains, and `schedule` cron
    expressions explained with the next 5 run times in UTC (computed by a built-in cron implementation,
    including the day-of-month OR day-of-week rule). Flags congested schedules (minute 0), intervals under
    5 minutes, and reminds that scheduled workflows run only on the default branch and are disabled after
    60 days of repository inactivity."""
    now = datetime.now(timezone.utc)
    return clip("\n\n".join(_explain(d, now) for _, d in load_docs(_sb(), path)))


@tool
def permissions_review(path: str = ".") -> str:
    """Show the effective GITHUB_TOKEN permissions of every job (job-level replaces workflow-level; absent
    means the repository default), infer what each job actually needs from the actions and gh/git commands
    it uses, flag write access that looks unnecessary and permissions that are missing, and print a
    least-privilege `permissions:` block per job. The inference is heuristic and says when it is partial."""
    return clip(_review([d for _, d in load_docs(_sb(), path)]))


@tool
def job_graph(path: str = ".") -> str:
    """Draw each workflow's job `needs:` graph as text and as a Mermaid diagram, group jobs into waves
    that can run in parallel, and show the critical path (longest dependency chain) plus a worst-case
    duration bound from timeout-minutes. Reports cycles."""
    return clip("\n\n".join(_render_graph(d) for _, d in load_docs(_sb(), path)))


@tool
def pin_actions_plan(path: str = ".", online: bool = False) -> str:
    """List every `uses:` that is not pinned to a full commit SHA (grouped by action version, with
    file:line) and how to pin each. With online=false (default) nothing touches the network and you get
    `git ls-remote` instructions. With online=true each tag or branch is resolved to its commit SHA through
    api.github.com only (annotated tags are dereferenced; results cached; honest rate-limit messages; an
    optional GITHUB_TOKEN in the server's environment raises the limit and is sent only to that host).
    Output is a plan as text: nothing is written."""
    docs = [d for _, d in load_docs(_sb(), path)]
    return clip(_plan(docs, online, _gh() if online else None))


@tool
def fix_preview(path: str) -> str:
    """Show a unified diff of the safe automatic fixes for a workflow file (or every workflow under a
    directory): add a top-level `permissions: contents: read` when every job is recognised as read-only,
    move injectable `${{ github.event.* }}` expressions out of `run:` scripts into step `env:` variables,
    and replace `::set-output` with $GITHUB_OUTPUT. The patched text is re-linted to prove the findings
    disappear and none are introduced. Never writes the file: apply the diff yourself. Lists what needs a
    manual change."""
    sb = _sb()
    parts = []
    for real in discover(sb, path):
        _, text = sb.read_text(real)
        parts.append(_preview(sb.display(real), text, make_loader(sb, real), _disabled))
    return clip("\n\n".join(parts))


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="workflowlint-mcp",
        description="MCP server that audits GitHub Actions workflows (offline, read-only by default).",
    )
    p.add_argument("--dir", default=None, help="Only files inside this directory can be read "
                   "(default: the current directory).")
    p.add_argument("--disable", action="append", default=[], metavar="IDS",
                   help="Comma-separated rule ids to turn off, e.g. GHA1013,GHA1021 (repeatable).")
    p.add_argument("--github-api-url", default=None, help=argparse.SUPPRESS)  # tests point this at a fake server
    p.add_argument("--version", action="version", version=f"workflowlint-mcp {__version__}")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    ids = [i.strip().upper() for chunk in args.disable for i in chunk.split(",") if i.strip()]
    try:
        configure(args.dir, ids, args.github_api_url)
    except UserError as e:
        print(f"workflowlint-mcp: {e}", file=sys.stderr)
        raise SystemExit(2) from e
    mcp.run()


if __name__ == "__main__":
    main()
